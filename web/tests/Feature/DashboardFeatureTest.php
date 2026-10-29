<?php

namespace Tests\Feature;

use App\Models\LlmProfile;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class DashboardFeatureTest extends TestCase
{
    use RefreshDatabase;

    public function test_dashboard_requires_login_and_operator_can_view_it(): void
    {
        $this->get('/')->assertRedirect(route('login'));
        $this->actingAs(User::factory()->create())->get('/')->assertOk()->assertSee('Mulai pemindaian');
    }

    public function test_profile_api_key_is_encrypted_and_never_returned_to_settings(): void
    {
        $this->actingAs(User::factory()->create())->post(route('profiles.store'), [
            'model' => 'hunter', 'api_base' => 'http://localhost:20128/v1', 'api_key' => 'test-secret-key',
        ])->assertRedirect(route('settings'));
        $profile = LlmProfile::firstOrFail();
        $this->assertNotSame('test-secret-key', $profile->getRawOriginal('api_key'));
        $this->assertSame('test-secret-key', $profile->api_key);
        $this->assertSame('hunter', $profile->name);
        $this->assertSame('openai/hunter', $profile->runnerProfile()['model']);
        $this->actingAs(User::first())->get(route('settings'))->assertOk()->assertDontSee('test-secret-key')->assertSee('Key tersembunyi')->assertDontSee('Nama profil')->assertDontSee('API route')->assertDontSee('tool calling');
    }

    public function test_connection_test_returns_inline_status_without_redirecting_to_scan(): void
    {
        $owner = User::factory()->create();
        $profile = LlmProfile::create(['user_id' => $owner->id, 'name' => 'hunter', 'model' => 'openai/hunter', 'api_base' => 'http://localhost:20128/v1', 'api_type' => 'chat_completions', 'api_key' => 'connection-secret']);
        Http::fakeSequence()
            ->push(['choices' => [['message' => ['content' => 'ok']]]], 200)
            ->push(['error' => ['message' => 'Invalid key connection-secret']], 401);
        $this->actingAs($owner)->postJson(route('profiles.test', $profile))->assertOk()->assertJsonPath('status', 'connected')->assertDontSee('connection-secret');
        $this->actingAs($owner)->postJson(route('profiles.test', $profile))->assertOk()->assertJsonPath('status', 'failed')->assertJsonPath('error', 'Invalid key [redacted]')->assertDontSee('connection-secret');
        $this->actingAs(User::factory()->create())->postJson(route('profiles.test', $profile))->assertNotFound();
    }

    public function test_source_repositories_and_credentials_in_url_are_rejected(): void
    {
        $user = User::factory()->create();
        $profile = LlmProfile::create(['user_id' => $user->id, 'name' => 'local', 'model' => 'openai/local', 'api_type' => 'chat_completions']);
        foreach (['https://github.com/org/repository', 'https://user:password@lab.example.com'] as $target) {
            $this->actingAs($user)->post(route('scans.store'), ['target' => $target, 'mode' => 'quick', 'llm_profile_id' => $profile->id])->assertSessionHasErrors('target');
        }
        $this->assertDatabaseCount('scans', 0);
    }

    public function test_operator_cannot_use_another_users_profile(): void
    {
        $owner = User::factory()->create();
        $other = User::factory()->create();
        $profile = LlmProfile::create(['user_id' => $owner->id, 'name' => 'Owner model', 'model' => 'openai/owner', 'api_type' => 'chat_completions']);
        $this->actingAs($other)->post(route('scans.store'), ['target' => 'https://lab.example.com', 'mode' => 'quick', 'llm_profile_id' => $profile->id])->assertNotFound();
        $this->actingAs($other)->get(route('settings'))->assertOk()->assertDontSee('Owner model');
        $this->assertDatabaseCount('scans', 0);
    }

    public function test_scan_snapshots_profile_and_creates_history(): void
    {
        $user = User::factory()->create();
        $profile = LlmProfile::create(['user_id' => $user->id, 'name' => 'Hunter', 'model' => 'openai/hunter', 'api_base' => 'http://localhost:20128/v1', 'api_type' => 'chat_completions', 'api_key' => 'private-key']);
        $response = $this->actingAs($user)->post(route('scans.store'), ['target' => 'https://lab.example.com', 'instruction' => 'Periksa kontrol akses.', 'mode' => 'standard', 'llm_profile_id' => $profile->id, 'max_budget' => 2]);
        $scan = Scan::firstOrFail();
        $response->assertRedirect(route('scans.show', $scan));
        $this->assertSame('queued', $scan->status);
        $this->assertSame('private-key', $scan->llm_snapshot['api_key']);
        $profile->update(['api_key' => 'rotated-key']);
        $this->assertSame('private-key', $scan->fresh()->llm_snapshot['api_key']);
    }

    public function test_context_mode_migration_preserves_existing_scans_and_is_repeatable(): void
    {
        $user = User::factory()->create();
        $scan = Scan::create(['user_id' => $user->id, 'kind' => 'scan', 'target' => 'https://lab.example', 'mode' => 'standard', 'status' => 'completed', 'llm_snapshot' => [], 'findings' => [['id' => 'preserved']]]);
        Schema::table('scans', function (Blueprint $table): void {
            $table->dropColumn('context_mode');
        });
        $migration = require database_path('migrations/2026_10_25_073805_add_context_mode_to_existing_scans_table.php');
        $migration->up();
        $this->assertFalse($scan->fresh()->context_mode);
        $this->assertSame([['id' => 'preserved']], $scan->fresh()->findings);
        $scan->update(['context_mode' => true]);
        $migration->up();
        $migration->down();
        $this->assertTrue($scan->fresh()->context_mode);
    }

    public function test_context_mode_selection_reaches_runner_without_changing_old_scans(): void
    {
        config(['pentesin.runner_token' => 'test-runner-token']);
        $user = User::factory()->create();
        $profile = LlmProfile::create(['user_id' => $user->id, 'name' => 'Test', 'model' => 'openai/test', 'api_type' => 'chat_completions']);
        $this->actingAs($user)->post(route('scans.store'), ['target' => 'https://lab.example', 'mode' => 'standard', 'llm_profile_id' => $profile->id, 'context_mode' => '1'])->assertSessionHasNoErrors();
        $scan = Scan::firstOrFail();
        $this->assertTrue($scan->context_mode);
        $this->withToken('test-runner-token')->postJson(route('runner.claim'))->assertOk()->assertJsonPath('job.context_mode', true);
    }

    public function test_internal_runner_requires_token_and_claims_one_job(): void
    {
        config(['pentesin.runner_token' => 'test-runner-token']);
        $user = User::factory()->create();
        $profile = LlmProfile::create(['user_id' => $user->id, 'name' => 'Hunter', 'model' => 'openai/hunter', 'api_type' => 'chat_completions', 'api_key' => 'hidden']);
        $scan = Scan::create(['kind' => 'scan', 'target' => 'https://lab.example.com', 'instruction' => '', 'mode' => 'quick', 'status' => 'queued', 'user_id' => $user->id, 'llm_profile_id' => $profile->id, 'llm_snapshot' => $profile->runnerProfile(), 'findings' => []]);
        $this->postJson('/api/internal/runner/v1/claim')->assertUnauthorized();
        $claimed = $this->withToken('test-runner-token')->postJson('/api/internal/runner/v1/claim')->assertOk()->assertJsonPath('job.id', $scan->id)->assertJsonPath('job.profile.api_key', 'hidden');
        $this->withToken('test-runner-token')->postJson('/api/internal/runner/v1/claim')->assertJsonPath('job', null);
        $this->assertSame('running', $scan->fresh()->status);
        $this->assertNotEmpty($claimed->json('job.lease_token'));
    }

    public function test_expired_runner_lease_blocks_chat_and_marks_run_interrupted(): void
    {
        $user = User::factory()->create();
        $profile = LlmProfile::create(['user_id' => $user->id, 'name' => 'Hunter', 'model' => 'openai/hunter', 'api_type' => 'chat_completions']);
        $scan = Scan::create(['kind' => 'scan', 'target' => 'https://lab.example', 'instruction' => '', 'mode' => 'quick', 'status' => 'running', 'user_id' => $user->id, 'llm_profile_id' => $profile->id, 'llm_snapshot' => $profile->runnerProfile(), 'findings' => [], 'lease_token' => 'expired-lease', 'lease_expires_at' => now()->subMinute()]);
        $this->actingAs($user)->post(route('scans.messages', $scan), ['agent_id' => 'root', 'message' => 'More tests'])->assertStatus(409);
        $this->actingAs($user)->get(route('scans.feed', $scan))->assertOk()->assertJsonPath('scan.status', 'interrupted');
        $this->assertDatabaseCount('scan_commands', 0);
    }

    public function test_scan_feed_cursor_does_not_skip_events_past_batch_limit(): void
    {
        $user = User::factory()->create();
        $profile = LlmProfile::create(['user_id' => $user->id, 'name' => 'Feed test', 'model' => 'openai/test', 'api_type' => 'chat_completions']);
        $scan = Scan::create(['user_id' => $user->id, 'kind' => 'scan', 'target' => 'https://lab.example.com', 'instruction' => '', 'mode' => 'quick', 'status' => 'running', 'llm_profile_id' => $profile->id, 'llm_snapshot' => $profile->runnerProfile(), 'findings' => []]);
        foreach (range(1, 201) as $number) {
            $scan->events()->create(['source_id' => "event-{$number}", 'version' => 0, 'agent_id' => 'root', 'type' => 'message', 'data' => ['content' => "message {$number}"]]);
        }
        $first = $this->actingAs($user)->get(route('scans.feed', $scan))->assertOk();
        $this->assertCount(200, $first->json('events'));
        $this->assertSame(200, $first->json('cursor'));
        $second = $this->actingAs($user)->get(route('scans.feed', [$scan, 'after' => 200]))->assertOk();
        $this->assertCount(1, $second->json('events'));
        $this->assertSame(201, $second->json('events.0.id'));
        $this->assertSame(201, $second->json('cursor'));
    }

    public function test_terminal_runner_can_upload_allowlisted_artifact_but_only_owner_can_download(): void
    {
        $owner = User::factory()->create();
        $other = User::factory()->create();
        $profile = LlmProfile::create(['user_id' => $owner->id, 'name' => 'Artifacts', 'model' => 'openai/test', 'api_type' => 'chat_completions']);
        $scan = Scan::create(['user_id' => $owner->id, 'kind' => 'scan', 'target' => 'https://lab.example', 'instruction' => '', 'mode' => 'quick', 'status' => 'completed', 'llm_profile_id' => $profile->id, 'llm_snapshot' => $profile->runnerProfile(), 'findings' => [], 'lease_token' => 'terminal-lease', 'lease_expires_at' => now()->subMinute()]);
        config(['pentesin.runner_token' => 'test-runner-token']);
        $this->withToken('test-runner-token')->postJson("/api/internal/runner/v1/scans/{$scan->id}/artifacts/findings.sarif", ['lease_token' => 'terminal-lease', 'content_base64' => base64_encode('{"runs":[]}')])->assertOk();
        $this->withToken('test-runner-token')->postJson("/api/internal/runner/v1/scans/{$scan->id}/artifacts/findings.sarif", ['lease_token' => 'terminal-lease', 'content_base64' => base64_encode('{"runs":[{"replacement":true}]}')])->assertStatus(409);
        $this->assertSame(['findings.sarif'], $scan->fresh()->artifacts);
        $this->actingAs($other)->get(route('scans.artifacts', [$scan, 'findings.sarif']))->assertNotFound();
        $this->actingAs($owner)->get(route('scans.artifacts', [$scan, 'findings.sarif']))->assertOk()->assertHeader('cache-control', 'no-store, private');
        $this->actingAs($owner)->get(route('scans.artifacts', [$scan, '../.env']))->assertNotFound();
    }

    public function test_runner_heartbeat_persists_graph_transcript_and_enqueues_chat(): void
    {
        config(['pentesin.runner_token' => 'test-runner-token']);
        $user = User::factory()->create();
        $profile = LlmProfile::create(['user_id' => $user->id, 'name' => 'Hunter', 'model' => 'openai/hunter', 'api_type' => 'chat_completions', 'api_key' => 'echo-secret']);
        $scan = Scan::create(['user_id' => $user->id, 'kind' => 'scan', 'target' => 'https://lab.example.com', 'instruction' => '', 'mode' => 'quick', 'status' => 'running', 'llm_profile_id' => $profile->id, 'llm_snapshot' => $profile->runnerProfile(), 'findings' => [], 'lease_token' => 'lease-token', 'lease_expires_at' => now()->addMinute()]);
        $this->withToken('test-runner-token')->postJson("/api/internal/runner/v1/scans/{$scan->id}/heartbeat", [
            'lease_token' => 'lease-token', 'phase' => 'Recon', 'agents' => [['id' => 'root', 'parent_id' => null, 'name' => 'Root', 'status' => 'running']], 'events' => [], 'findings' => [],
        ])->assertOk();
        $this->actingAs($user)->post(route('scans.messages', $scan), ['agent_id' => 'root', 'message' => 'Periksa API lebih jauh.'])->assertStatus(202)->assertJsonPath('command.status', 'queued');
        $finding = ['id' => 'finding-1', 'severity' => 'high', 'title' => 'IDOR', 'description' => 'Endpoint exposes another record.'];
        $this->withToken('test-runner-token')->postJson("/api/internal/runner/v1/scans/{$scan->id}/heartbeat", [
            'lease_token' => 'lease-token', 'phase' => 'Recon', 'agents' => [['id' => 'root', 'parent_id' => null, 'name' => 'Root', 'status' => 'running']],
            'events' => [['source_id' => 'event-1', 'version' => 0, 'agent_id' => 'root', 'type' => 'tool', 'data' => ['tool_name' => 'http_request', 'status' => 'running']]], 'findings' => [$finding],
            'artifacts' => ['findings.sarif'],
        ])->assertOk()->assertJsonPath('commands.0.message', 'Periksa API lebih jauh.');
        $this->assertDatabaseHas('scan_events', ['source_id' => 'event-1', 'version' => 0]);
        $this->withToken('test-runner-token')->postJson("/api/internal/runner/v1/scans/{$scan->id}/heartbeat", [
            'lease_token' => 'lease-token', 'agents' => [['id' => 'root', 'parent_id' => null, 'name' => 'Root', 'status' => 'running']],
            'events' => [['source_id' => 'event-1', 'version' => 1, 'agent_id' => 'root', 'type' => 'tool', 'data' => ['tool_name' => 'http_request', 'status' => 'completed', 'result' => ['status_code' => 200], 'api_key' => 'echo-secret']]], 'findings' => [],
        ])->assertOk();
        $event = $scan->events()->where('version', 1)->firstOrFail();
        $this->assertSame('[redacted]', $event->data['api_key']);
        $this->assertSame(2, $scan->events()->where('source_id', 'event-1')->count());
        $this->assertDatabaseHas('scan_agents', ['agent_id' => 'root']);
        $this->assertSame('finding-1', $scan->fresh()->findings[0]['id']);
        $this->assertSame(['findings.sarif'], $scan->fresh()->artifacts);
        $this->assertDatabaseHas('scan_agents', ['scan_id' => $scan->id, 'agent_id' => 'root']);
        $this->assertDatabaseHas('scan_events', ['scan_id' => $scan->id, 'source_id' => 'event-1']);
        $feed = $this->actingAs($user)->get(route('scans.feed', $scan))->assertOk()->assertJsonPath('agents.0.name', 'Root')->assertJsonPath('scan.artifacts', ['findings.sarif']);
        $feed->assertJsonPath('cursor', $scan->events()->max('id'));
        $feed->assertJsonPath('events.0.version', 0);
        $this->assertSame('[redacted]', $scan->events()->where('version', 1)->firstOrFail()->data['api_key']);
        $this->assertNotSame('echo-secret', $scan->fresh()->getRawOriginal('llm_snapshot'));
        $this->assertStringNotContainsString('echo-secret', json_encode($event->data));
    }
}
