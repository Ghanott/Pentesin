<?php

namespace Tests\Feature;

use App\Models\Scan;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class ScanDeleteTest extends TestCase
{
    use RefreshDatabase;

    private function scanFor(User $user, array $attributes = []): Scan
    {
        return Scan::create($attributes + [
            'user_id' => $user->id,
            'kind' => 'scan',
            'target' => 'https://lab.example',
            'mode' => 'standard',
            'status' => 'completed',
            'llm_snapshot' => ['model' => 'openai/mock'],
            'findings' => [],
        ]);
    }

    public function test_operator_can_delete_a_finished_scan_with_its_artifacts(): void
    {
        Storage::fake('local');
        $user = User::factory()->create();
        $scan = $this->scanFor($user);
        Storage::disk('local')->put("pentesin_runs/web-{$scan->id}/vulnerabilities.json", '{}');

        $this->actingAs($user)
            ->delete(route('scans.destroy', $scan))
            ->assertRedirect(route('scans.history'))
            ->assertSessionHas('status', 'Pemindaian dihapus.');

        $this->assertDatabaseMissing('scans', ['id' => $scan->id]);
        Storage::disk('local')->assertDirectoryEmpty("pentesin_runs/web-{$scan->id}");
    }

    public function test_active_scan_cannot_be_deleted(): void
    {
        foreach (['queued', 'running'] as $status) {
            $user = User::factory()->create();
            $scan = $this->scanFor($user, ['status' => $status]);

            $this->actingAs($user)->delete(route('scans.destroy', $scan))->assertStatus(409);

            $this->assertDatabaseHas('scans', ['id' => $scan->id]);
        }
    }

    public function test_operator_cannot_delete_another_users_scan(): void
    {
        $owner = User::factory()->create();
        $other = User::factory()->create();
        $scan = $this->scanFor($owner);

        $this->actingAs($other)->delete(route('scans.destroy', $scan))->assertNotFound();

        $this->assertDatabaseHas('scans', ['id' => $scan->id]);
    }

    public function test_guests_are_redirected_to_login(): void
    {
        $scan = $this->scanFor(User::factory()->create());

        $this->delete(route('scans.destroy', $scan))->assertRedirect(route('login'));

        $this->assertDatabaseHas('scans', ['id' => $scan->id]);
    }
}
