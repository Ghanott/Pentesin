<?php

namespace App\Http\Controllers\Internal;

use App\Http\Controllers\Controller;
use App\Models\Scan;
use App\Models\ScanCommand;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class RunnerController extends Controller
{
    public function claim(): JsonResponse
    {
        return DB::transaction(function (): JsonResponse {
            DB::table('runner_states')->insertOrIgnore(['id' => 1]);
            DB::table('runner_states')->where('id', 1)->lockForUpdate()->first();
            $activeScans = Scan::where('status', 'running')->lockForUpdate()->get();
            if ($activeScans->isNotEmpty()) {
                foreach ($activeScans as $active) {
                    if ($active->lease_expires_at?->isPast()) {
                        $active->update(['status' => 'interrupted', 'error' => 'Lease runner berakhir. Periksa runner sebelum menjalankan kembali.', 'finished_at' => now()]);
                    }
                }

                return response()->json(['job' => null]);
            }
            $scan = Scan::where('status', 'queued')->oldest()->lockForUpdate()->first();
            if (! $scan) {
                return response()->json(['job' => null]);
            }
            $lease = Str::random(64);
            $scan->update(['status' => 'running', 'phase' => 'Menyiapkan runner', 'lease_token' => $lease, 'lease_expires_at' => now()->addSeconds(90), 'started_at' => now()]);

            return response()->json(['job' => $scan->only(['id', 'kind', 'target', 'instruction', 'mode', 'max_budget', 'context_mode']) + ['resume' => $scan->agents()->exists(), 'lease_token' => $lease, 'profile' => $scan->llm_snapshot, 'run_dir' => base_path('../pentesin_runs/web-'.$scan->id)]])->header('Cache-Control', 'no-store');
        });
    }

    private function fence(Scan $scan, string $lease, bool $terminalRetry = false): void
    {
        abort_unless($scan->lease_token && hash_equals($scan->lease_token, $lease), 409, 'Lease tidak valid.');
        abort_unless(($terminalRetry && in_array($scan->status, ['running', 'interrupted', 'completed', 'failed', 'stopped'], true)) || ($scan->status === 'running' && $scan->lease_expires_at?->isFuture()), 409, 'Lease berakhir.');
    }

    private function redact(mixed $value, ?string $secret): mixed
    {
        if (is_array($value)) {
            $clean = [];
            foreach ($value as $key => $item) {
                $clean[$key] = preg_match('/api[_-]?key|token|secret|password|credential/i', (string) $key) ? '[redacted]' : $this->redact($item, $secret);
            }

            return $clean;
        }
        if (is_string($value) && $secret) {
            return str_replace($secret, '[redacted]', $value);
        }

        return $value;
    }

    public function heartbeat(Request $request, Scan $scan): JsonResponse
    {
        abort_if(strlen($request->getContent()) > 8 * 1024 * 1024, 413);
        $findingRules = [
            'findings.*.action' => ['sometimes', Rule::in(['upsert', 'delete'])],
            'findings.*.severity' => ['sometimes', 'string', Rule::in(['info', 'low', 'medium', 'high', 'critical'])],
            'findings.*.cvss' => ['sometimes', 'nullable', 'numeric', 'between:0,10'],
        ];
        foreach (['title', 'description', 'impact', 'target', 'technical_analysis', 'poc_description', 'poc_script_code', 'remediation_steps', 'cve', 'cwe', 'endpoint', 'method', 'timestamp', 'agent_id', 'agent_name', 'finding_class', 'fix_effort', 'confidence', 'fix_verification', 'fix_pr_body'] as $field) {
            $findingRules["findings.*.$field"] = ['sometimes', 'nullable', 'string', 'max:1000000'];
        }
        foreach (['evidence', 'assumptions', 'counterevidence', 'severity_change_conditions', 'cvss_breakdown', 'code_locations', 'http_exchange_ids', 'dependency_metadata'] as $field) {
            $findingRules["findings.*.$field"] = ['sometimes', 'nullable'];
        }
        $data = $request->validate([
            ...$findingRules,
            'lease_token' => ['required', 'string'], 'phase' => ['nullable', 'string', 'max:500'],
            'status' => ['sometimes', Rule::in(['running', 'completed', 'failed', 'stopped', 'interrupted'])],
            'error' => ['nullable', 'string', 'max:2000'], 'test_result' => ['nullable', 'array'], 'artifacts' => ['sometimes', 'array', 'max:10'], 'artifacts.*' => ['string', 'in:penetration_test_report.md,vulnerabilities.json,findings.sarif,coverage.json'],
            'agents' => ['sometimes', 'array', 'max:500'], 'agents.*.id' => ['required', 'string', 'max:200'],
            'agents.*.parent_id' => ['nullable', 'string', 'max:200'], 'agents.*.name' => ['required', 'string', 'max:500'], 'agents.*.status' => ['required', 'string', 'max:50'],
            'events' => ['sometimes', 'array', 'max:1000'], 'events.*.source_id' => ['required', 'string', 'max:200'],
            'events.*.agent_id' => ['nullable', 'string', 'max:200'], 'events.*.type' => ['required', 'string', 'max:100'], 'events.*.version' => ['required', 'integer', 'min:0'], 'events.*.data' => ['required', 'array'],
            'findings' => ['sometimes', 'array', 'max:1000'], 'findings.*.id' => ['required', 'string', 'max:200'],
            'deleted_finding_ids' => ['sometimes', 'array', 'max:1000'], 'deleted_finding_ids.*' => ['string', 'max:200'],
        ]);

        return DB::transaction(function () use ($scan, $data): JsonResponse {
            $scan = Scan::lockForUpdate()->findOrFail($scan->id);
            $terminal = isset($data['status']) && $data['status'] !== 'running';
            $this->fence($scan, $data['lease_token'], $terminal);
            if (in_array($scan->status, ['completed', 'failed', 'stopped'], true)) {
                abort_unless($terminal && $data['status'] === $scan->status, 409, 'Scan sudah berakhir.');

                return response()->json(['commands' => []]);
            }
            $secret = $scan->llm_snapshot['api_key'] ?? null;
            foreach ($data['agents'] ?? [] as $agent) {
                $scan->agents()->updateOrCreate(['agent_id' => $agent['id']], ['parent_id' => $agent['parent_id'] ?? null, 'name' => $this->redact($agent['name'], $secret), 'status' => $agent['status']]);
            }
            foreach ($data['events'] ?? [] as $event) {
                $scan->events()->firstOrCreate(
                    ['source_id' => $event['source_id'], 'version' => $event['version']],
                    ['agent_id' => $event['agent_id'] ?? null, 'type' => $event['type'], 'data' => $this->redact($event['data'], $secret)],
                );
            }
            $findings = collect($scan->findings ?? [])->keyBy('id');
            foreach ($data['findings'] ?? [] as $finding) {
                if (($finding['action'] ?? '') === 'delete') {
                    $findings->forget($finding['id']);
                } else {
                    unset($finding['action']);
                    $findings->put($finding['id'], $this->redact($finding, $secret));
                }
            }
            foreach ($data['deleted_finding_ids'] ?? [] as $id) {
                $findings->forget($id);
            }
            $changes = ['lease_expires_at' => now()->addSeconds(90), 'findings' => $findings->values()->all()];
            foreach (['phase', 'error', 'test_result', 'artifacts'] as $key) {
                if (array_key_exists($key, $data)) {
                    $changes[$key] = $this->redact($data[$key], $secret);
                }
            }
            if (isset($data['status'])) {
                $changes['status'] = $data['status'];
                if ($data['status'] !== 'running') {
                    $changes['finished_at'] = now();
                    $scan->commands()->where('status', 'queued')->update(['status' => 'failed', 'error' => 'Scan berakhir sebelum instruksi terkirim.']);
                }
            }
            $scan->update($changes);

            return response()->json(['commands' => $scan->status === 'running' ? $scan->commands()->where('status', 'queued')->oldest()->get(['id', 'type', 'agent_id', 'message']) : []])->header('Cache-Control', 'no-store');
        });
    }

    public function acknowledge(Request $request, Scan $scan, ScanCommand $command): JsonResponse
    {
        $data = $request->validate(['lease_token' => ['required', 'string'], 'status' => ['required', Rule::in(['delivered', 'failed'])], 'error' => ['nullable', 'string', 'max:2000']]);
        abort_unless($command->scan_id === $scan->id, 404);

        return DB::transaction(function () use ($scan, $command, $data): JsonResponse {
            $scan = Scan::lockForUpdate()->findOrFail($scan->id);
            $this->fence($scan, $data['lease_token']);
            $command->refresh();
            if ($command->status === 'queued') {
                $command->update(['status' => $data['status'], 'error' => $this->redact($data['error'] ?? null, $scan->llm_snapshot['api_key'] ?? null)]);
            }

            return response()->json(['ok' => true]);
        });
    }
}
