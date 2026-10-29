<?php

namespace Tests\Feature;

use App\Models\LlmProfile;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class RunnerBridgeTest extends TestCase
{
    use RefreshDatabase;

    public function test_heartbeat_preserves_finding_details_and_redacts_secrets(): void
    {
        config(['pentesin.runner_token' => 'test-runner-token']);
        $user = User::factory()->create();
        $scan = Scan::create(['kind' => 'scan', 'target' => 'https://lab.example', 'instruction' => '', 'mode' => 'quick', 'status' => 'running', 'user_id' => $user->id, 'llm_snapshot' => ['api_key' => 'private-model-key'], 'findings' => [], 'lease_token' => 'lease', 'lease_expires_at' => now()->addMinute()]);
        $finding = [
            'id' => 'finding-1', 'action' => 'upsert', 'title' => 'Example finding',
            'severity' => 'high', 'description' => 'Evidence private-model-key',
            'impact' => 'Example impact', 'target' => 'https://lab.example',
            'technical_analysis' => 'Analysis', 'poc_description' => 'Reproduce',
            'poc_script_code' => 'print(1)', 'remediation_steps' => 'Fix access checks',
            'evidence' => ['request' => 'GET /example'], 'cvss' => 7.5, 'cwe' => 'CWE-862',
        ];
        $this->withToken('test-runner-token')->postJson(route('runner.heartbeat', $scan), [
            'lease_token' => 'lease', 'findings' => [$finding],
        ])->assertOk();
        unset($finding['action']);
        $finding['description'] = 'Evidence [redacted]';
        $this->assertEquals($finding, $scan->fresh()->findings[0]);
    }

    public function test_user_prompt_requeues_failed_scan_and_preserves_agent_history(): void
    {
        config(['pentesin.runner_token' => 'test-runner-token']);
        $user = User::factory()->create();
        $scan = Scan::create(['kind' => 'scan', 'target' => 'https://lab.example', 'mode' => 'quick', 'status' => 'failed', 'user_id' => $user->id, 'llm_snapshot' => ['model' => 'openai/test'], 'findings' => [['id' => 'finding-1', 'title' => 'Preserved']], 'lease_token' => 'old-lease', 'lease_expires_at' => now()->addMinute(), 'finished_at' => now()]);
        $scan->agents()->create(['agent_id' => 'root', 'name' => 'Root', 'status' => 'failed']);
        $this->actingAs($user)->postJson(route('scans.messages', $scan), ['agent_id' => 'root', 'message' => 'Continue with the existing evidence'])->assertStatus(202);
        $this->assertSame('queued', $scan->fresh()->status);
        $this->assertSame('finding-1', $scan->fresh()->findings[0]['id']);
        $this->assertNull($scan->fresh()->lease_token);
        $this->withToken('test-runner-token')->postJson(route('runner.claim'))->assertOk()->assertJsonPath('job.resume', true)->assertJsonPath('job.id', $scan->id);
        $lease = $scan->fresh()->lease_token;
        $this->withToken('test-runner-token')->postJson(route('runner.heartbeat', $scan), ['lease_token' => 'old-lease'])->assertStatus(409);
        $this->withToken('test-runner-token')->postJson(route('runner.heartbeat', $scan), ['lease_token' => $lease])->assertOk()->assertJsonPath('commands.0.message', 'Continue with the existing evidence');
        $scan->update(['status' => 'stopped']);
        $this->actingAs($user)->postJson(route('scans.messages', $scan), ['agent_id' => 'root', 'message' => 'Continue'])->assertStatus(409);
    }

    public function test_terminal_delivery_after_expiry_preserves_resume_fencing(): void
    {
        config(['pentesin.runner_token' => 'test-runner-token']);
        $user = User::factory()->create();
        $scan = Scan::create(['kind' => 'scan', 'target' => 'https://lab.example', 'mode' => 'quick', 'status' => 'running', 'user_id' => $user->id, 'llm_snapshot' => ['model' => 'openai/test'], 'findings' => [], 'lease_token' => 'old-lease', 'lease_expires_at' => now()->subMinute()]);
        $scan->agents()->create(['agent_id' => 'root', 'name' => 'Root', 'status' => 'completed']);
        $endpoint = route('runner.heartbeat', $scan);
        $payload = ['lease_token' => 'old-lease', 'status' => 'completed'];
        $this->withToken('test-runner-token')->postJson($endpoint, ['lease_token' => 'old-lease'])->assertStatus(409);
        $scan->update(['status' => 'interrupted']);
        $this->withToken('test-runner-token')->postJson($endpoint, $payload)->assertOk();
        $this->assertSame('completed', $scan->fresh()->status);
        $finished = $scan->fresh()->finished_at;
        $this->travel(5)->minutes();
        $this->withToken('test-runner-token')->postJson($endpoint, $payload)->assertOk();
        $this->assertEquals($finished, $scan->fresh()->finished_at);
        $this->withToken('test-runner-token')->postJson($endpoint, ['lease_token' => 'old-lease', 'status' => 'failed'])->assertStatus(409);
        $this->actingAs($user)->postJson(route('scans.messages', $scan), ['agent_id' => 'root', 'message' => 'Continue from checkpoint'])->assertStatus(202);
        $this->assertSame('queued', $scan->fresh()->status);
        $this->withToken('test-runner-token')->postJson($endpoint, $payload)->assertStatus(409);
        $this->withToken('test-runner-token')->postJson(route('runner.claim'))->assertOk()->assertJsonPath('job.resume', true);
        $this->withToken('test-runner-token')->postJson($endpoint, $payload)->assertStatus(409);
        $this->assertSame('running', $scan->fresh()->status);
    }

    public function test_runner_token_is_required_and_only_one_scan_is_claimed(): void
    {
        config(['pentesin.runner_token' => 'test-runner-token']);
        $user = User::factory()->create();
        $profile = LlmProfile::create(['user_id' => $user->id, 'name' => 'Test', 'model' => 'openai/test', 'api_type' => 'chat_completions', 'api_key' => 'secret']);
        $scan = Scan::create(['kind' => 'scan', 'target' => 'https://lab.example', 'instruction' => '', 'mode' => 'quick', 'status' => 'queued', 'user_id' => $user->id, 'llm_profile_id' => $profile->id, 'llm_snapshot' => $profile->runnerProfile(), 'findings' => []]);
        $this->postJson('/api/internal/runner/v1/claim')->assertUnauthorized();
        $this->withToken('test-runner-token')->postJson('/api/internal/runner/v1/claim')->assertOk()->assertJsonPath('job.id', $scan->id)->assertJsonPath('job.profile.api_key', 'secret');
        $this->withToken('test-runner-token')->postJson('/api/internal/runner/v1/claim')->assertJsonPath('job', null);
        $this->assertSame('running', $scan->fresh()->status);
    }
}
