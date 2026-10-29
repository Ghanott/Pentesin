<?php

namespace Tests\Feature;

use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class DashboardViewTest extends TestCase
{
    use RefreshDatabase;

    public function test_dashboard_redirects_guests_to_private_login(): void
    {
        $this->get('/')->assertRedirect(route('login'));
    }

    public function test_operator_can_view_empty_dashboard(): void
    {
        $this->actingAs(User::factory()->create())->get('/')->assertOk()->assertSee('Mulai pemindaian')->assertDontSee('id="history-title"', false)
            ->assertSee('Target pengujian')->assertSee('Sebelum memulai')
            ->assertDontSee('name="max_budget"', false)->assertDontSee('↗')->assertDontSee('Satu target. Banyak perspektif.');
    }

    public function test_history_is_private_and_excludes_model_tests_and_other_owners(): void
    {
        $this->get(route('scans.history'))->assertRedirect(route('login'));
        $owner = User::factory()->create();
        $other = User::factory()->create();
        foreach ([
            [$owner, 'scan', 'https://owned-lab.example'],
            [$owner, 'model_test', 'LLM-TEST-ONLY'],
            [$other, 'scan', 'https://other-owner.example'],
        ] as [$user, $kind, $target]) {
            Scan::create(['user_id' => $user->id, 'kind' => $kind, 'target' => $target, 'mode' => 'quick', 'status' => 'completed', 'llm_snapshot' => ['model' => 'openai/mock'], 'findings' => []]);
        }
        $this->actingAs($owner)->get(route('scans.history'))->assertOk()
            ->assertSee('https://owned-lab.example')->assertDontSee('LLM-TEST-ONLY')->assertDontSee('https://other-owner.example');
        $this->actingAs($owner)->get(route('dashboard'))->assertOk()->assertDontSee('https://owned-lab.example');
    }
}
