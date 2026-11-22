<?php

namespace Tests\Feature;

use App\Models\IntegrationSetting;
use App\Models\LlmProfile;
use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ArtexAdaptationFeatureTest extends TestCase
{
    use RefreshDatabase;

    public function test_integration_keys_are_encrypted_and_never_shown_in_settings(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)
            ->put(route('integrations.update'), [
                'web_search_provider' => 'tavily',
                'tavily_api_key' => 'tvly-super-secret',
                'exa_api_key' => 'exa-super-secret',
            ])
            ->assertRedirect();

        $record = IntegrationSetting::where('user_id', $user->id)->firstOrFail();
        $this->assertSame('tavily', $record->web_search_provider);
        $this->assertNotSame('tvly-super-secret', $record->getRawOriginal('tavily_api_key'));
        $this->assertSame('tvly-super-secret', $record->tavily_api_key);
        $this->assertSame('exa-super-secret', $record->exa_api_key);

        $this->actingAs($user)
            ->get(route('settings'))
            ->assertOk()
            ->assertDontSee('tvly-super-secret')
            ->assertDontSee('exa-super-secret')
            ->assertSee('Integrasi Web Search');
    }

    public function test_scan_stores_noise_profile_and_encrypted_auth_credentials(): void
    {
        $user = User::factory()->create();
        $profile = LlmProfile::create([
            'user_id' => $user->id,
            'name' => 'Default',
            'model' => 'openai/gpt-4o',
            'api_base' => 'https://api.openai.com/v1',
            'api_key' => 'sk-test',
        ]);

        $this->actingAs($user)
            ->post(route('scans.store'), [
                'target' => 'https://app.example.com',
                'mode' => 'standard',
                'noise_profile' => 'quiet',
                'auth_credentials_raw' => "user_a=Bearer tokA\nuser_b=Cookie: sid=xyz",
                'llm_profile_id' => $profile->id,
            ])
            ->assertRedirect();

        $scan = Scan::firstOrFail();
        $this->assertSame('quiet', $scan->noise_profile);
        $this->assertSame(['user_a=Bearer tokA', 'user_b=Cookie: sid=xyz'], $scan->auth_credentials);
        $this->assertNotSame('user_a=Bearer tokA', (string) $scan->getRawOriginal('auth_credentials'));
    }

    public function test_retest_finding_queues_dedicated_retest_scan_and_enforces_ownership(): void
    {
        $owner = User::factory()->create();
        $other = User::factory()->create();
        $profile = LlmProfile::create([
            'user_id' => $owner->id,
            'name' => 'Default',
            'model' => 'openai/gpt-4o',
            'api_base' => 'https://api.openai.com/v1',
            'api_key' => 'sk-test',
        ]);

        $scan = Scan::create([
            'user_id' => $owner->id,
            'target' => 'https://app.example.com',
            'mode' => 'standard',
            'kind' => 'scan',
            'status' => 'completed',
            'llm_profile_id' => $profile->id,
            'llm_snapshot' => $profile->runnerProfile(),
            'findings' => [
                [
                    'id' => 'vuln-0001',
                    'title' => 'IDOR on /api/users/2',
                    'severity' => 'high',
                    'endpoint' => '/api/users/2',
                    'poc_description' => 'Replay with user B token.',
                    'poc_script_code' => 'curl -H "Authorization: Bearer B" https://app.example.com/api/users/2',
                ],
            ],
        ]);

        $this->actingAs($other)
            ->post(route('scans.retest', [$scan, 'vuln-0001']))
            ->assertNotFound();

        $this->actingAs($owner)
            ->post(route('scans.retest', [$scan, 'vuln-0001']))
            ->assertRedirect();

        $retest = Scan::where('kind', 'retest')->firstOrFail();
        $this->assertSame('queued', $retest->status);
        $this->assertSame('vuln-0001', $retest->retest_target_finding['finding_id'] ?? null);
    }

    public function test_history_displays_cross_scan_target_diff(): void
    {
        $user = User::factory()->create();
        $profile = LlmProfile::create([
            'user_id' => $user->id,
            'name' => 'Default',
            'model' => 'openai/gpt-4o',
            'api_base' => 'https://api.openai.com/v1',
            'api_key' => 'sk-test',
        ]);

        Scan::create([
            'user_id' => $user->id,
            'target' => 'https://target.example.com',
            'mode' => 'standard',
            'kind' => 'scan',
            'status' => 'completed',
            'llm_profile_id' => $profile->id,
            'llm_snapshot' => $profile->runnerProfile(),
            'findings' => [
                ['id' => 'vuln-0001', 'title' => 'Old Bug', 'endpoint' => '/old'],
                ['id' => 'vuln-0002', 'title' => 'Shared Bug', 'endpoint' => '/shared'],
            ],
            'created_at' => now()->subHour(),
        ]);

        Scan::create([
            'user_id' => $user->id,
            'target' => 'https://target.example.com/',
            'mode' => 'standard',
            'kind' => 'scan',
            'status' => 'completed',
            'llm_profile_id' => $profile->id,
            'llm_snapshot' => $profile->runnerProfile(),
            'findings' => [
                ['id' => 'vuln-0003', 'title' => 'Shared Bug', 'endpoint' => '/shared'],
                ['id' => 'vuln-0004', 'title' => 'New Bug', 'endpoint' => '/new'],
            ],
            'created_at' => now(),
        ]);

        $this->actingAs($user)
            ->get(route('scans.history'))
            ->assertOk()
            ->assertSee('+1 baru · 1 tetap · -1 fixed');
    }
}
