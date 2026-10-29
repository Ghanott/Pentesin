<?php

namespace App\Http\Controllers;

use App\Models\LlmProfile;
use App\Models\Scan;
use Illuminate\Contracts\View\View;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\Rule;
use Symfony\Component\HttpFoundation\StreamedResponse;

class DashboardController extends Controller
{
    public function index(): View
    {
        $this->expireOwnerLeases();

        return view('dashboard');
    }

    public function history(): View
    {
        $this->expireOwnerLeases();

        return view('history', ['scans' => Scan::where('user_id', auth()->id())->where('kind', 'scan')->latest()->paginate(20)]);
    }

    public function settings(): View
    {
        return view('settings', ['profiles' => LlmProfile::where('user_id', auth()->id())->orderBy('name')->get()->map(fn (LlmProfile $profile) => (object) ['id' => $profile->id, 'name' => $profile->name, 'model' => $profile->model, 'api_base' => $profile->api_base, 'api_type' => $profile->api_type, 'has_key' => filled($profile->api_key)])]);
    }

    public function show(Scan $scan): View
    {
        $this->expireOwnerLeases();
        abort_unless($scan->user_id === request()->user()->id, 404);

        return view('scan', ['scan' => $scan->fresh(), 'artifacts' => array_intersect($scan->artifacts ?? [], ['penetration_test_report.md', 'vulnerabilities.json', 'findings.sarif', 'coverage.json'])]);
    }

    public function store(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'target' => ['required', 'string', 'max:2048', function (string $attribute, mixed $value, \Closure $fail): void {
                $url = str_contains($value, '://') ? $value : 'https://'.$value;
                $parts = parse_url($url);
                if (! $parts || ! in_array($parts['scheme'] ?? '', ['http', 'https'], true) || empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) || str_ends_with(strtolower($value), '.git') || preg_match('/[\s\\\\]/', $value)) {
                    $fail('Target harus domain, IP, atau URL HTTP(S) tanpa kredensial.');

                    return;
                }
                $host = strtolower($parts['host']);
                if (in_array($host, ['github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org', 'sr.ht', 'sourcehut.org'], true) && count(array_filter(explode('/', $parts['path'] ?? ''))) >= 2) {
                    $fail('Repository sumber tidak didukung. Gunakan target web/API black-box.');
                }
                $plain = trim($host, '[]');
                if (! filter_var($plain, FILTER_VALIDATE_IP) && $plain !== 'localhost' && ! filter_var($plain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                    $fail('Domain target tidak valid.');
                }
            }],
            'instruction' => ['nullable', 'string', 'max:10000'],
            'mode' => ['required', Rule::in(['quick', 'standard', 'deep'])],
            'context_mode' => ['sometimes', 'accepted'],
            'llm_profile_id' => ['required', 'integer', 'exists:llm_profiles,id'],
            'max_budget' => ['nullable', 'numeric', 'min:0.01', 'max:1000'],
        ]);
        $profile = LlmProfile::where('user_id', $request->user()->id)->findOrFail($data['llm_profile_id']);
        $mode = $data['mode'] === 'quick' ? 'standard' : $data['mode'];
        $scan = Scan::create([
            'user_id' => $request->user()->id, 'target' => $data['target'], 'instruction' => $data['instruction'] ?? '',
            'mode' => $mode, 'context_mode' => (bool) ($data['context_mode'] ?? false), 'kind' => 'scan', 'status' => 'queued', 'llm_profile_id' => $profile->id,
            'max_budget' => $data['max_budget'] ?? null, 'llm_snapshot' => $profile->runnerProfile(), 'findings' => [],
        ]);

        return redirect()->route('scans.show', $scan)->with('status', 'Pemindaian masuk antrean runner.');
    }

    private function ownedScan(Request $request, Scan $scan): Scan
    {
        abort_unless($scan->user_id === $request->user()->id, 404);

        return $scan;
    }

    public function feed(Request $request, Scan $scan): JsonResponse
    {
        $scan = $this->ownedScan($request, $scan);
        $this->expireOwnerLeases();
        $scan->refresh();
        $data = $request->validate(['after' => ['nullable', 'integer', 'min:0']]);
        $after = (int) ($data['after'] ?? 0);
        $events = $scan->events()->where('id', '>', $after)->orderBy('id')->limit(200)->get(['id', 'source_id', 'version', 'agent_id', 'type', 'data', 'created_at']);

        return response()->json([
            'scan' => $scan->only(['id', 'target', 'instruction', 'status', 'phase', 'error', 'test_result', 'started_at', 'finished_at', 'artifacts']) + ['artifacts' => array_intersect($scan->artifacts ?? [], ['penetration_test_report.md', 'vulnerabilities.json', 'findings.sarif', 'coverage.json'])],
            'agents' => $scan->agents()->orderBy('id')->get()->map(fn ($agent) => ['id' => $agent->agent_id, 'parent_id' => $agent->parent_id, 'name' => $agent->name, 'status' => $agent->status, 'created_at' => $agent->created_at]),
            'events' => $events,
            'cursor' => $events->last()?->id ?? $after,
            'findings' => $scan->findings ?? [],
            'commands' => $scan->commands()->latest()->limit(100)->get(['id', 'agent_id', 'type', 'status', 'created_at']),
        ])->header('Cache-Control', 'no-store');
    }

    public function message(Request $request, Scan $scan): JsonResponse
    {
        $scan = $this->ownedScan($request, $scan);
        $data = $request->validate(['agent_id' => ['required', 'string', 'max:200'], 'message' => ['required', 'string', 'max:4000']]);

        return DB::transaction(function () use ($scan, $data, $request): JsonResponse {
            $locked = Scan::where('user_id', $request->user()->id)->lockForUpdate()->findOrFail($scan->id);
            abort_if($locked->status === 'running' && ! $locked->lease_expires_at?->isFuture(), 409, 'Lease runner berakhir.');
            $agent = $locked->agents()->where('agent_id', $data['agent_id'])->firstOrFail();
            if ($locked->kind === 'scan' && in_array($locked->status, ['completed', 'failed', 'interrupted'], true)) {
                $locked->update(['status' => 'queued', 'phase' => 'Menunggu runner untuk melanjutkan', 'error' => null, 'finished_at' => null, 'lease_token' => null, 'lease_expires_at' => null]);
            } else {
                abort_unless(($locked->status === 'running' && $locked->lease_expires_at?->isFuture()) || ($locked->status === 'queued' && $locked->agents()->exists()), 409, 'Scan tidak aktif.');
            }
            $command = $locked->commands()->create(['type' => 'message', 'agent_id' => $agent->agent_id, 'message' => $data['message'], 'status' => 'queued']);
            $locked->events()->create(['source_id' => 'web-user-'.$command->id, 'version' => 0, 'agent_id' => $agent->agent_id, 'type' => 'user_message', 'data' => ['role' => 'user', 'content' => $data['message'], 'metadata' => ['source' => 'web_dashboard']]]);

            return response()->json(['command' => $command->only(['id', 'type', 'agent_id', 'status'])], 202);
        });
    }

    public function stop(Request $request, Scan $scan): RedirectResponse
    {
        $scan = $this->ownedScan($request, $scan);
        DB::transaction(function () use ($scan, $request): void {
            $locked = Scan::where('user_id', $request->user()->id)->lockForUpdate()->findOrFail($scan->id);
            if ($locked->status === 'queued') {
                $locked->update(['status' => 'stopped', 'finished_at' => now()]);
            } elseif ($locked->status === 'running') {
                $locked->commands()->firstOrCreate(['type' => 'stop', 'status' => 'queued']);
            }
        });

        return back()->with('status', 'Permintaan berhenti dicatat. Tunggu cleanup runner.');
    }

    public function destroy(Request $request, Scan $scan): RedirectResponse
    {
        $scan = $this->ownedScan($request, $scan);
        abort_if($scan->active(), 409, 'Hentikan pemindaian sebelum menghapus.');

        DB::transaction(function () use ($scan): void {
            Storage::disk('local')->deleteDirectory("pentesin_runs/web-{$scan->id}");
            $scan->delete();
        });

        return redirect()->route('scans.history')->with('status', 'Pemindaian dihapus.');
    }

    private function profileData(Request $request, bool $updating = false): array
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'model' => ['required', 'string', 'max:200'],
            'api_base' => ['required', 'url:http,https', 'max:2048', function (string $attribute, mixed $value, \Closure $fail): void {
                if ($value && (parse_url($value, PHP_URL_USER) !== null || parse_url($value, PHP_URL_PASS) !== null || parse_url($value, PHP_URL_QUERY) !== null || parse_url($value, PHP_URL_FRAGMENT) !== null)) {
                    $fail('Base URL tidak boleh mengandung kredensial, query, atau fragment.');
                }
            }],
            'api_key' => ['nullable', 'string', 'max:4096'], 'clear_key' => ['sometimes', 'boolean'],
        ]);
        if ($updating && empty($data['api_key'])) {
            unset($data['api_key']);
        }
        if ($request->boolean('clear_key')) {
            $data['api_key'] = null;
        }
        unset($data['clear_key']);
        $data['name'] = trim($data['name']);
        $data['model'] = trim($data['model']);
        $data['api_type'] = 'chat_completions';

        return $data;
    }

    public function storeProfile(Request $request): RedirectResponse
    {
        LlmProfile::create($this->profileData($request) + ['user_id' => $request->user()->id]);

        return redirect()->route('settings')->with('status', 'Profil LLM tersimpan.');
    }

    private function ownedProfile(Request $request, LlmProfile $profile): LlmProfile
    {
        abort_unless($profile->user_id === $request->user()->id, 404);

        return $profile;
    }

    public function updateProfile(Request $request, LlmProfile $profile): RedirectResponse
    {
        $profile = $this->ownedProfile($request, $profile);
        $profile->update($this->profileData($request, true));

        return redirect()->route('settings')->with('status', 'Profil diperbarui; scan aktif tidak berubah.');
    }

    public function destroyProfile(Request $request, LlmProfile $profile): RedirectResponse
    {
        $profile = $this->ownedProfile($request, $profile);
        $profile->delete();

        return redirect()->route('settings')->with('status', 'Profil dihapus.');
    }

    public function testProfile(Request $request, LlmProfile $profile): JsonResponse
    {
        $profile = $this->ownedProfile($request, $profile);
        $base = rtrim($profile->api_base ?: 'https://api.openai.com/v1', '/');
        $endpoint = str_ends_with($base, '/chat/completions') ? $base : $base.'/chat/completions';
        $model = str_starts_with($profile->model, 'openai/') ? substr($profile->model, 7) : $profile->model;
        $started = hrtime(true);
        try {
            $caBundle = base_path('../.venv/Lib/site-packages/certifi/cacert.pem');
            $req = Http::timeout(15)->acceptJson()->withOptions(['verify' => is_file($caBundle) ? $caBundle : false]);
            if (filled($profile->api_key)) {
                $req = $req->withToken($profile->api_key);
            }
            $res = $req->post($endpoint, ['model' => $model, 'messages' => [['role' => 'user', 'content' => 'test']], 'max_tokens' => 16]);
            $latency = (int) round((hrtime(true) - $started) / 1_000_000);
            if ($res->successful() && filled(data_get($res->json(), 'choices.0.message.content')) || filled(data_get($res->json(), 'choices.0.message.reasoning_content')) || is_array(data_get($res->json(), 'choices')) && $res->successful()) {
                return response()->json(['status' => 'connected', 'latency_ms' => $latency])->header('Cache-Control', 'no-store');
            }
            $err = data_get($res->json(), 'error.message') ?: data_get($res->json(), 'message') ?: 'HTTP '.$res->status();
        } catch (\Throwable $e) {
            $err = $e->getMessage();
        }
        if (filled($profile->api_key)) {
            $err = str_replace($profile->api_key, '[redacted]', (string) $err);
        }

        return response()->json(['status' => 'failed', 'error' => mb_substr((string) $err, 0, 300)])->header('Cache-Control', 'no-store');
    }

    public function profileTestResult(Request $request, LlmProfile $profile, Scan $scan): JsonResponse
    {
        $this->ownedProfile($request, $profile);
        $this->ownedScan($request, $scan);
        abort_unless($scan->kind === 'model_test' && $scan->llm_profile_id === $profile->id, 404);
        $this->expireOwnerLeases();
        $scan->refresh();
        $result = $scan->test_result;
        $pending = in_array($scan->status, ['queued', 'running'], true);

        return response()->json([
            'status' => $pending ? 'testing' : (($scan->status === 'completed' && ($result['ok'] ?? false)) ? 'connected' : 'failed'),
            'error' => $pending ? null : ($result['error'] ?? $scan->error),
        ])->header('Cache-Control', 'no-store');
    }

    public function storeArtifact(Request $request, Scan $scan, string $name): JsonResponse
    {
        abort_unless(in_array($name, ['penetration_test_report.md', 'vulnerabilities.json', 'findings.sarif', 'coverage.json'], true), 404);
        $data = $request->validate(['lease_token' => ['required', 'string'], 'content_base64' => ['required', 'string', 'max:1400000']]);
        $bytes = base64_decode($data['content_base64'], true);
        abort_if($bytes === false || strlen($bytes) > 1_000_000, 413);

        return DB::transaction(function () use ($scan, $name, $bytes, $data): JsonResponse {
            $locked = Scan::lockForUpdate()->findOrFail($scan->id);
            $leaseValid = $locked->lease_token && hash_equals($locked->lease_token, $data['lease_token']);
            $running = $locked->status === 'running' && $locked->lease_expires_at?->isFuture();
            $firstTerminalUpload = in_array($locked->status, ['completed', 'failed', 'stopped'], true) && ! in_array($name, $locked->artifacts ?? [], true);
            abort_unless($leaseValid && ($running || $firstTerminalUpload), 409, 'Lease tidak valid.');
            $path = "pentesin_runs/web-{$locked->id}/{$name}";
            abort_unless(Storage::disk('local')->put($path, $bytes), 500, 'Artifact storage failed.');
            $locked->update(['artifacts' => array_values(array_unique([...($locked->artifacts ?? []), $name]))]);

            return response()->json(['stored' => true, 'name' => $name]);
        });
    }

    public function artifact(Request $request, Scan $scan, string $name): StreamedResponse
    {
        abort_unless($scan->user_id === $request->user()->id, 404);
        abort_unless(in_array($name, ['penetration_test_report.md', 'vulnerabilities.json', 'findings.sarif', 'coverage.json'], true) && in_array($name, $scan->artifacts ?? [], true), 404);
        $path = "pentesin_runs/web-{$scan->id}/{$name}";
        abort_unless(Storage::disk('local')->exists($path), 404);

        return Storage::disk('local')->download($path, $name, ['Cache-Control' => 'private, no-store']);
    }

    private function expireOwnerLeases(): void
    {
        Scan::where('user_id', auth()->id())->where('status', 'running')->where('lease_expires_at', '<', now())->update(['status' => 'interrupted', 'error' => 'Runner terputus; periksa proses runner sebelum menjalankan ulang.', 'finished_at' => now()]);
    }
}
