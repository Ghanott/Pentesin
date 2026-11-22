<?php

namespace App\Http\Controllers;

use App\Models\IntegrationSetting;
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

        $scans = Scan::where('user_id', auth()->id())
            ->whereIn('kind', ['scan', 'retest'])
            ->latest()
            ->paginate(20);

        $allUserScans = Scan::where('user_id', auth()->id())
            ->where('kind', 'scan')
            ->where('status', 'completed')
            ->orderBy('created_at')
            ->get(['id', 'target', 'findings', 'created_at']);

        $prevByTarget = [];
        $targetDiffs = [];
        foreach ($allUserScans as $completed) {
            $normTarget = $this->normalizeTargetKey((string) $completed->target);
            $currentKeys = $this->findingFingerprints($completed->findings ?? []);
            if (isset($prevByTarget[$normTarget])) {
                $prevKeys = $prevByTarget[$normTarget];
                $targetDiffs[$completed->id] = [
                    'new' => count(array_diff($currentKeys, $prevKeys)),
                    'persisted' => count(array_intersect($currentKeys, $prevKeys)),
                    'fixed' => count(array_diff($prevKeys, $currentKeys)),
                ];
            }
            $prevByTarget[$normTarget] = $currentKeys;
        }

        return view('history', [
            'scans' => $scans,
            'targetDiffs' => $targetDiffs,
        ]);
    }

    /**
     * Normalize a target string to host+scheme key for cross-scan comparison.
     */
    private function normalizeTargetKey(string $target): string
    {
        $trimmed = trim($target);
        $url = str_contains($trimmed, '://') ? $trimmed : 'https://'.$trimmed;
        $parts = parse_url($url);
        if (! is_array($parts) || empty($parts['host'])) {
            return strtolower($trimmed);
        }
        $host = strtolower((string) $parts['host']);
        $port = isset($parts['port']) ? ':'.$parts['port'] : '';

        return $host.$port;
    }

    /**
     * @param  array<int, mixed>  $findings
     * @return array<int, string>
     */
    private function findingFingerprints(array $findings): array
    {
        $keys = [];
        foreach ($findings as $finding) {
            if (! is_array($finding)) {
                continue;
            }
            $title = strtolower(trim((string) ($finding['title'] ?? '')));
            $endpoint = strtolower(trim((string) ($finding['endpoint'] ?? '')));
            if ($title !== '') {
                $keys[] = $title.'|'.$endpoint;
            }
        }

        return array_values(array_unique($keys));
    }

    public function settings(): View
    {
        $integration = IntegrationSetting::where('user_id', auth()->id())->first();

        return view('settings', [
            'profiles' => LlmProfile::where('user_id', auth()->id())->orderBy('name')->get()->map(fn (LlmProfile $profile) => (object) ['id' => $profile->id, 'name' => $profile->name, 'model' => $profile->model, 'api_base' => $profile->api_base, 'api_type' => $profile->api_type, 'has_key' => filled($profile->api_key)]),
            'integration' => (object) [
                'web_search_provider' => $integration?->web_search_provider ?? 'auto',
                'has_exa' => filled($integration?->exa_api_key),
                'has_perplexity' => filled($integration?->perplexity_api_key),
                'has_tavily' => filled($integration?->tavily_api_key),
                'has_brave' => filled($integration?->brave_api_key),
            ],
        ]);
    }

    public function updateIntegrations(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'web_search_provider' => ['required', Rule::in(['auto', 'exa', 'perplexity', 'tavily', 'brave'])],
            'exa_api_key' => ['nullable', 'string', 'max:4096'],
            'perplexity_api_key' => ['nullable', 'string', 'max:4096'],
            'tavily_api_key' => ['nullable', 'string', 'max:4096'],
            'brave_api_key' => ['nullable', 'string', 'max:4096'],
        ]);

        $record = IntegrationSetting::firstOrNew(['user_id' => $request->user()->id]);
        $record->web_search_provider = $data['web_search_provider'];
        foreach (['exa_api_key', 'perplexity_api_key', 'tavily_api_key', 'brave_api_key'] as $field) {
            if (filled($data[$field] ?? null)) {
                $record->{$field} = trim((string) $data[$field]);
            }
        }
        $record->save();

        return back()->with('status', 'Konfigurasi integrasi Web Search tersimpan terenkripsi.');
    }

    public function retestFinding(Request $request, Scan $scan, string $findingId): RedirectResponse
    {
        $scan = $this->ownedScan($request, $scan);
        $finding = collect($scan->findings ?? [])->first(
            fn (mixed $item): bool => is_array($item) && (string) ($item['id'] ?? '') === $findingId
        );
        abort_unless(is_array($finding), 404, 'Temuan tidak ditemukan.');

        $integration = IntegrationSetting::where('user_id', $request->user()->id)->first();
        $retestScan = Scan::create([
            'user_id' => $request->user()->id,
            'target' => $scan->target,
            'instruction' => 'Retest temuan '.($finding['id'] ?? $findingId).': '.($finding['title'] ?? ''),
            'mode' => 'standard',
            'context_mode' => (bool) $scan->context_mode,
            'smart_recon' => false,
            'noise_profile' => $scan->noise_profile ?: 'off',
            'auth_credentials' => $scan->auth_credentials,
            'integration_snapshot' => $integration?->runnerPayload() ?? $scan->integration_snapshot,
            'retest_target_finding' => [
                'parent_scan_id' => $scan->id,
                'finding_id' => (string) ($finding['id'] ?? $findingId),
                'title' => (string) ($finding['title'] ?? ''),
                'endpoint' => (string) ($finding['endpoint'] ?? ''),
                'poc_description' => (string) ($finding['poc_description'] ?? ''),
                'poc_script_code' => (string) ($finding['poc_script_code'] ?? ''),
            ],
            'kind' => 'retest',
            'status' => 'queued',
            'llm_profile_id' => $scan->llm_profile_id,
            'max_budget' => $scan->max_budget,
            'llm_snapshot' => $scan->llm_snapshot,
            'findings' => [],
        ]);

        return redirect()->route('scans.show', $retestScan)->with('status', 'Retest temuan masuk antrean runner.');
    }

    public function show(Scan $scan): View
    {
        $this->expireOwnerLeases();
        abort_unless($scan->user_id === request()->user()->id, 404);

        return view('scan', [
            'scan' => $scan->fresh(),
            'artifacts' => array_intersect($scan->artifacts ?? [], ['penetration_test_report.md', 'vulnerabilities.json', 'coverage.json']),
        ]);
    }

    public function report(Request $request, Scan $scan): View
    {
        $this->expireOwnerLeases();
        abort_unless($scan->user_id === request()->user()->id, 404);

        $lang = $request->query('lang', 'id') === 'en' ? 'en' : 'id';
        $findings = $scan->findings ?? [];

        $narrativesPath = "pentesin_runs/web-{$scan->id}/report_narratives.json";
        $hasAiReport = false;
        if (Storage::disk('local')->exists($narrativesPath)) {
            $narrativesData = json_decode(Storage::disk('local')->get($narrativesPath), true);
            if (is_array($narrativesData) && ! empty($narrativesData['findings'])) {
                $hasAiReport = true;
                $mapped = [];
                foreach ($narrativesData['findings'] as $idx => $item) {
                    $key = null;
                    if (isset($item['finding_id']) && is_string($item['finding_id'])) {
                        $key = $item['finding_id'];
                    } elseif (isset($item['id']) && is_string($item['id'])) {
                        $key = $item['id'];
                    }
                    if ($key) {
                        $mapped[$key] = $item;
                    }
                    $mapped["idx_{$idx}"] = $item;
                }
                foreach ($findings as $idx => &$f) {
                    $fId = $f['id'] ?? null;
                    $transContainer = ($fId && isset($mapped[$fId])) ? $mapped[$fId] : ($mapped["idx_{$idx}"] ?? null);
                    if ($transContainer && isset($transContainer[$lang]) && is_array($transContainer[$lang])) {
                        $trans = $transContainer[$lang];
                        if (! empty($trans['title'])) {
                            $f['title'] = $trans['title'];
                        }
                        if (! empty($trans['description'])) {
                            $f['description'] = $trans['description'];
                        }
                        if (! empty($trans['impact'])) {
                            $f['impact'] = $trans['impact'];
                        }
                        if (! empty($trans['technical_analysis'])) {
                            $f['technical_analysis'] = $trans['technical_analysis'];
                        }
                        if (! empty($trans['remediation'])) {
                            $f['remediation_steps'] = $trans['remediation'];
                        }
                        if (! empty($trans['remediation_steps'])) {
                            $f['remediation_steps'] = $trans['remediation_steps'];
                        }
                    }
                }
                unset($f);
            }
        }

        $severityOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
        usort($findings, function (array $a, array $b) use ($severityOrder): int {
            $sevA = strtolower($a['severity'] ?? 'info');
            $sevB = strtolower($b['severity'] ?? 'info');

            return ($severityOrder[$sevA] ?? 5) <=> ($severityOrder[$sevB] ?? 5);
        });

        return view('report', [
            'scan' => $scan->fresh(),
            'findings' => $findings,
            'lang' => $lang,
            'hasAiReport' => $hasAiReport,
        ]);
    }

    public function vaReport(Request $request, Scan $scan): View
    {
        $this->expireOwnerLeases();
        abort_unless($scan->user_id === $request->user()->id, 404);

        $lang = strtolower((string) $request->query('lang', 'id'));
        if (! in_array($lang, ['id', 'en'], true)) {
            $lang = 'id';
        }

        $scan = $scan->fresh(['agents']);
        $findings = is_array($scan->findings) ? $scan->findings : [];
        $severityOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
        usort($findings, function (array $a, array $b) use ($severityOrder): int {
            $sevA = strtolower((string) ($a['severity'] ?? 'info'));
            $sevB = strtolower((string) ($b['severity'] ?? 'info'));

            return ($severityOrder[$sevA] ?? 5) <=> ($severityOrder[$sevB] ?? 5);
        });

        $coverage = null;
        $coveragePath = "pentesin_runs/web-{$scan->id}/coverage.json";
        if (Storage::disk('local')->exists($coveragePath)) {
            $decoded = json_decode((string) Storage::disk('local')->get($coveragePath), true);
            if (is_array($decoded)) {
                $coverage = $decoded;
            }
        }

        $hasCoverageData = is_array($coverage);
        $entries = [];
        if ($hasCoverageData && is_array($coverage['entries'] ?? null)) {
            $entries = array_values(array_filter($coverage['entries'], 'is_array'));
        } elseif (! empty($findings)) {
            // Fallback for older scans executed before coverage.json tracking existed.
            foreach ($findings as $finding) {
                $entries[] = [
                    'surface' => (string) ($finding['endpoint'] ?? ($finding['target'] ?? $scan->target)),
                    'risk_area' => (string) ($finding['title'] ?? 'Security Finding'),
                    'outcome' => 'reported',
                    'outcome_label' => 'Reported',
                    'evidence' => (string) ($finding['description'] ?? ($finding['impact'] ?? '')),
                    'recorded_by' => (string) ($finding['agent'] ?? 'Pentesin'),
                    'source' => 'legacy_findings',
                ];
            }
        }

        $outcomeOrder = [
            'reported' => 0,
            'needs_follow_up' => 1,
            'no_issue_found' => 2,
            'ruled_out' => 3,
            'not_applicable' => 4,
        ];
        usort($entries, function (array $a, array $b) use ($outcomeOrder): int {
            $orderA = $outcomeOrder[(string) ($a['outcome'] ?? '')] ?? 5;
            $orderB = $outcomeOrder[(string) ($b['outcome'] ?? '')] ?? 5;
            if ($orderA !== $orderB) {
                return $orderA <=> $orderB;
            }

            $surfaceCmp = strnatcasecmp((string) ($a['surface'] ?? ''), (string) ($b['surface'] ?? ''));
            if ($surfaceCmp !== 0) {
                return $surfaceCmp;
            }

            return strnatcasecmp((string) ($a['risk_area'] ?? ''), (string) ($b['risk_area'] ?? ''));
        });

        $outcomes = [
            'reported' => 0,
            'no_issue_found' => 0,
            'ruled_out' => 0,
            'not_applicable' => 0,
            'needs_follow_up' => 0,
        ];
        foreach ($entries as $entry) {
            $key = (string) ($entry['outcome'] ?? '');
            if (array_key_exists($key, $outcomes)) {
                $outcomes[$key]++;
            }
        }
        $outcomes['safe_total'] = $outcomes['no_issue_found'] + $outcomes['ruled_out'] + $outcomes['not_applicable'];
        $outcomes['total_tested'] = count($entries);

        $machineObserved = is_array($coverage['machine_observed'] ?? null) ? $coverage['machine_observed'] : [];
        $agents = [];
        if (is_array($machineObserved['agents'] ?? null) && ! empty($machineObserved['agents'])) {
            $agents = array_values(array_filter($machineObserved['agents'], 'is_array'));
        } else {
            foreach ($scan->agents as $agent) {
                $agents[] = [
                    'agent_id' => $agent->agent_id,
                    'agent_name' => $agent->name,
                    'status' => $agent->status,
                    'skills' => is_array($agent->skills) ? $agent->skills : [],
                    'is_root' => (bool) ($agent->is_root ?? false),
                ];
            }
        }

        $skillsExercised = is_array($machineObserved['skills_exercised'] ?? null)
            ? array_values(array_filter($machineObserved['skills_exercised'], 'is_string'))
            : [];

        $gaps = is_array($coverage['gaps'] ?? null)
            ? array_values(array_filter($coverage['gaps'], 'is_array'))
            : [];

        $completeness = is_array($coverage['completeness'] ?? null) ? $coverage['completeness'] : [
            'complete' => in_array($scan->status, ['completed'], true) && $hasCoverageData,
            'scan_status' => $scan->status,
            'exit_reason' => $scan->error_message ?? '',
            'caveats' => [],
        ];

        return view('va-report', [
            'scan' => $scan,
            'lang' => $lang,
            'hasCoverageData' => $hasCoverageData,
            'coverage' => $coverage,
            'entries' => $entries,
            'outcomes' => $outcomes,
            'findings' => $findings,
            'agents' => $agents,
            'skillsExercised' => $skillsExercised,
            'gaps' => $gaps,
            'completeness' => $completeness,
        ]);
    }

    /**
     * Synthesize publication-grade bilingual narratives for scan findings.
     */
    public function synthesizeReport(Request $request, Scan $scan): JsonResponse
    {
        @ini_set('max_execution_time', '300');
        @set_time_limit(300);

        $this->expireOwnerLeases();
        $this->ownedScan($request, $scan);

        $validated = $request->validate([
            'finding_ids' => ['nullable', 'array', 'max:100'],
            'finding_ids.*' => ['string', 'max:200'],
            'language' => ['nullable', Rule::in(['id', 'en'])],
            'llm_profile_id' => ['nullable', 'integer'],
        ]);

        $findings = $scan->findings ?? [];
        if (empty($findings)) {
            return response()->json(['success' => false, 'error' => 'Tidak ada temuan kerentanan untuk diparafrase.']);
        }

        $candidates = $this->resolveSynthesisCandidates(
            $request,
            $scan,
            isset($validated['llm_profile_id']) ? (int) $validated['llm_profile_id'] : null,
        );
        if (empty($candidates)) {
            return response()->json(['success' => false, 'error' => 'Konfigurasi LLM tidak ditemukan. Atur profil LLM di menu Pengaturan.'], 422);
        }

        $allFindings = [];
        foreach (array_values($findings) as $idx => $f) {
            if (! is_array($f)) {
                continue;
            }
            $allFindings[] = [
                'id' => (string) ($f['id'] ?? 'vuln-'.$idx),
                'title' => (string) ($f['title'] ?? ''),
                'severity' => (string) ($f['severity'] ?? 'info'),
                'target' => (string) ($f['target'] ?? ''),
                'endpoint' => (string) ($f['endpoint'] ?? ''),
                'cwe' => (string) ($f['cwe'] ?? ''),
                'description' => $this->trimNarrativeField((string) ($f['description'] ?? ''), 1800),
                'impact' => $this->trimNarrativeField((string) ($f['impact'] ?? ''), 1000),
                'technical_analysis' => $this->trimNarrativeField((string) ($f['technical_analysis'] ?? ''), 1800),
                'remediation_steps' => $this->trimNarrativeField((string) ($f['remediation_steps'] ?? ''), 1000),
            ];
        }

        $requestedIds = array_values(array_unique($validated['finding_ids'] ?? []));
        $targetFindings = empty($requestedIds)
            ? $allFindings
            : array_values(array_filter(
                $allFindings,
                static fn (array $item): bool => in_array($item['id'], $requestedIds, true),
            ));

        if (empty($targetFindings)) {
            return response()->json(['success' => false, 'error' => 'Temuan yang diminta untuk diparafrase tidak ditemukan.'], 422);
        }

        $targetLanguages = isset($validated['language']) ? [$validated['language']] : ['id', 'en'];
        $isIncremental = ! empty($requestedIds) || isset($validated['language']);

        $caBundle = base_path('../.venv/Lib/site-packages/certifi/cacert.pem');
        $verifySsl = is_file($caBundle) ? $caBundle : false;

        $languageNarratives = [];
        $expectedIds = array_column($targetFindings, 'id');
        $activeCandidateIndex = 0;

        foreach ($targetLanguages as $language) {
            $languageName = $language === 'en' ? 'English' : 'Indonesian';
            $languageNarratives[$language] = [];

            foreach (array_chunk($targetFindings, 3) as $batch) {
                $chunkResult = $this->synthesizeBatchResilient(
                    $batch,
                    $language,
                    $languageName,
                    $candidates,
                    $activeCandidateIndex,
                    $verifySsl,
                );

                if (! $chunkResult['ok']) {
                    return response()->json(
                        ['success' => false, 'error' => $chunkResult['error']],
                        $chunkResult['status'],
                    );
                }

                $activeCandidateIndex = $chunkResult['candidate_index'];
                $languageNarratives[$language] += $chunkResult['narratives'];
            }

            if (count($languageNarratives[$language]) !== count($expectedIds)) {
                return response()->json(['success' => false, 'error' => "Sintesis {$languageName} tidak mencakup seluruh temuan."], 502);
            }
        }

        $savedCount = $this->persistSynthesisNarratives($scan, $allFindings, $languageNarratives, $isIncremental);
        if ($savedCount === null) {
            return response()->json(['success' => false, 'error' => 'Gagal menyimpan hasil parafrase.'], 500);
        }

        return response()->json(['success' => true, 'count' => $savedCount]);
    }

    /**
     * Build ordered deduplicated LLM endpoint candidates for synthesis.
     *
     * @return list<array{api_base: string, api_key: ?string, model: string, endpoint: string}>
     */
    private function resolveSynthesisCandidates(Request $request, Scan $scan, ?int $requestedProfileId): array
    {
        $rawCandidates = [];

        if ($requestedProfileId !== null) {
            $explicit = LlmProfile::where('user_id', $request->user()->id)->find($requestedProfileId);
            if ($explicit) {
                $rawCandidates[] = [
                    'api_base' => $explicit->api_base,
                    'api_key' => $explicit->api_key,
                    'model' => $explicit->model,
                ];
            }
        }

        $snapshot = is_array($scan->llm_snapshot) ? $scan->llm_snapshot : [];
        if (! empty($snapshot['api_base']) && ! empty($snapshot['model'])) {
            $rawCandidates[] = [
                'api_base' => $snapshot['api_base'],
                'api_key' => $snapshot['api_key'] ?? null,
                'model' => $snapshot['model'],
            ];
        }

        if ($scan->llm_profile_id) {
            $scanProfile = LlmProfile::where('user_id', $request->user()->id)->find($scan->llm_profile_id);
            if ($scanProfile) {
                $rawCandidates[] = [
                    'api_base' => $scanProfile->api_base,
                    'api_key' => $scanProfile->api_key,
                    'model' => $scanProfile->model,
                ];
            }
        }

        foreach (LlmProfile::where('user_id', $request->user()->id)->orderBy('id')->get() as $profile) {
            $rawCandidates[] = [
                'api_base' => $profile->api_base,
                'api_key' => $profile->api_key,
                'model' => $profile->model,
            ];
        }

        $candidates = [];
        $seen = [];
        foreach ($rawCandidates as $item) {
            if (empty($item['api_base']) || empty($item['model'])) {
                continue;
            }
            $base = rtrim((string) $item['api_base'], '/');
            $endpoint = str_ends_with($base, '/chat/completions') ? $base : $base.'/chat/completions';
            $rawModel = (string) $item['model'];
            $model = str_starts_with($rawModel, 'openai/') ? substr($rawModel, 7) : $rawModel;
            $dedupeKey = strtolower($endpoint.'|'.$model);
            if (isset($seen[$dedupeKey])) {
                continue;
            }
            $seen[$dedupeKey] = true;
            $candidates[] = [
                'api_base' => $base,
                'api_key' => $item['api_key'] ?? null,
                'model' => $model,
                'endpoint' => $endpoint,
            ];
        }

        return $candidates;
    }

    /**
     * Execute synthesis for a batch with profile fallback and automatic single-finding split on failure.
     *
     * @param  list<array<string, mixed>>  $batch
     * @param  list<array{api_base: string, api_key: ?string, model: string, endpoint: string}>  $candidates
     * @return array{ok: bool, narratives?: array<string, array<string, string>>, candidate_index?: int, error?: string, status?: int}
     */
    private function synthesizeBatchResilient(
        array $batch,
        string $language,
        string $languageName,
        array $candidates,
        int $preferredIndex,
        string|bool $verifySsl,
    ): array {
        $orderedIndexes = [$preferredIndex];
        foreach (array_keys($candidates) as $idx) {
            if ($idx !== $preferredIndex) {
                $orderedIndexes[] = $idx;
            }
        }

        $lastFailure = ['ok' => false, 'error' => "Gagal membuat narasi {$languageName}.", 'status' => 502];

        foreach ($orderedIndexes as $idx) {
            $result = $this->requestSynthesisBatch($batch, $language, $languageName, $candidates[$idx], $verifySsl);
            if ($result['ok']) {
                return [
                    'ok' => true,
                    'narratives' => $result['narratives'],
                    'candidate_index' => $idx,
                ];
            }
            $lastFailure = $result;
        }

        if (count($batch) > 1) {
            $splitNarratives = [];
            $workingIdx = $preferredIndex;
            foreach ($batch as $singleItem) {
                $singleRes = $this->synthesizeBatchResilient(
                    [$singleItem],
                    $language,
                    $languageName,
                    $candidates,
                    $workingIdx,
                    $verifySsl,
                );
                if (! $singleRes['ok']) {
                    return $singleRes;
                }
                $workingIdx = $singleRes['candidate_index'];
                $splitNarratives += $singleRes['narratives'];
            }

            return [
                'ok' => true,
                'narratives' => $splitNarratives,
                'candidate_index' => $workingIdx,
            ];
        }

        return $lastFailure;
    }

    /**
     * Send one chat-completion request for a batch of findings and parse strict/tolerant JSON narratives.
     *
     * @param  list<array<string, mixed>>  $batch
     * @param  array{api_base: string, api_key: ?string, model: string, endpoint: string}  $candidate
     * @return array{ok: bool, narratives?: array<string, array<string, string>>, error?: string, status?: int}
     */
    private function requestSynthesisBatch(
        array $batch,
        string $language,
        string $languageName,
        array $candidate,
        string|bool $verifySsl,
    ): array {
        $languageRequirement = $language === 'en'
            ? 'Write only in fluent professional English, following HackerOne VRT terminology.'
            : 'Tulis hanya dalam Bahasa Indonesia formal dengan terminologi keamanan siber yang tepat, sesuai standar BSSN / ISO 27001.';

        $prompt = "You are a Principal Penetration Tester and Lead Security Auditor. Rewrite publication-grade vulnerability report narratives for an international cybersecurity audit.\n";
        $prompt .= "Produce this request's output only in {$languageName}. {$languageRequirement}\n";
        $prompt .= "For EACH input finding, preserve the finding ID and provide high-quality title, description, impact, technical_analysis, and remediation. Do not invent facts or change severity.\n";
        $prompt .= "Target findings input (JSON):\n".json_encode($batch, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)."\n\n";
        $prompt .= "Return ONLY valid JSON, no markdown fences, thinking tags, or explanation, using this schema and this language key only:\n";
        $prompt .= json_encode([
            'findings' => [[
                'finding_id' => 'string',
                $language => [
                    'title' => '...',
                    'description' => '...',
                    'impact' => '...',
                    'technical_analysis' => '...',
                    'remediation' => '...',
                ],
            ]],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $timeoutSeconds = count($batch) === 1 ? 85 : 120;
        $client = Http::timeout($timeoutSeconds)->acceptJson()->withOptions(['verify' => $verifySsl]);
        if (filled($candidate['api_key'] ?? null)) {
            $client = $client->withToken((string) $candidate['api_key']);
        }

        try {
            $requestBody = [
                'model' => $candidate['model'],
                'reasoning_effort' => 'low',
                'messages' => [
                    ['role' => 'system', 'content' => 'You are an expert security report synthesizer. Output strictly valid JSON without code fences or surrounding commentary.'],
                    ['role' => 'user', 'content' => $prompt],
                ],
                'temperature' => 0.2,
                'max_tokens' => 8192,
            ];
            $res = $client->post($candidate['endpoint'], $requestBody);
            if ($res->status() === 400 || $res->status() === 422) {
                $errLower = strtolower((string) $res->body());
                if (str_contains($errLower, 'reasoning_effort') || str_contains($errLower, 'unsupported') || str_contains($errLower, 'unknown')) {
                    unset($requestBody['reasoning_effort']);
                    $res = $client->post($candidate['endpoint'], $requestBody);
                }
            }

            if (! $res->successful()) {
                $err = data_get($res->json(), 'error.message') ?: ('HTTP '.$res->status());

                return ['ok' => false, 'error' => "Gagal membuat narasi {$languageName}: ".$err, 'status' => 502];
            }

            $payloadJson = $res->json();
            $rawContent = (string) (data_get($payloadJson, 'choices.0.message.content') ?? '');
            if (trim($rawContent) === '') {
                $reasoning = (string) (data_get($payloadJson, 'choices.0.message.reasoning_content') ?? '');
                if (str_contains($reasoning, '{') && str_contains($reasoning, '"title"')) {
                    $rawContent = $reasoning;
                } else {
                    $finishReason = (string) (data_get($payloadJson, 'choices.0.finish_reason') ?? '');
                    $hint = $finishReason === 'length'
                        ? 'Model kehabisan token reasoning sebelum menulis output JSON.'
                        : 'Respons model kosong.';

                    return ['ok' => false, 'error' => "Format respons {$languageName} tidak valid ({$hint}).", 'status' => 502];
                }
            }

            $parsed = $this->decodeNarrativeJson($rawContent);
            if (! is_array($parsed)) {
                return ['ok' => false, 'error' => "Format respons {$languageName} tidak valid sebagai JSON temuan.", 'status' => 502];
            }

            $items = $parsed['findings'] ?? null;
            if (! is_array($items) && count($batch) === 1 && (isset($parsed['title']) || isset($parsed[$language]))) {
                $items = [$parsed];
            }
            if (! is_array($items)) {
                return ['ok' => false, 'error' => "Format respons {$languageName} tidak valid sebagai JSON temuan.", 'status' => 502];
            }

            $sourceById = [];
            foreach ($batch as $src) {
                $sourceById[$src['id']] = $src;
            }
            $batchIds = array_keys($sourceById);
            $byFindingId = [];

            foreach ($items as $translatedFinding) {
                if (! is_array($translatedFinding)) {
                    return ['ok' => false, 'error' => "Format temuan {$languageName} tidak valid.", 'status' => 502];
                }
                $findingId = $translatedFinding['finding_id'] ?? $translatedFinding['id'] ?? null;
                if ((! is_string($findingId) || ! in_array($findingId, $batchIds, true)) && count($batch) === 1 && empty($byFindingId)) {
                    $findingId = $batch[0]['id'];
                }
                $narrative = $translatedFinding[$language] ?? null;
                if (! is_array($narrative) && isset($translatedFinding['title'], $translatedFinding['description'])) {
                    $narrative = $translatedFinding;
                }
                if (! is_string($findingId) || ! in_array($findingId, $batchIds, true) || isset($byFindingId[$findingId]) || ! is_array($narrative)) {
                    return ['ok' => false, 'error' => "Respons {$languageName} tidak cocok dengan batch temuan.", 'status' => 502];
                }

                if (empty($narrative['remediation']) && ! empty($narrative['remediation_steps'])) {
                    $narrative['remediation'] = $narrative['remediation_steps'];
                }

                $source = $sourceById[$findingId];
                $normalized = [
                    'title' => trim((string) ($narrative['title'] ?? '')),
                    'description' => trim((string) ($narrative['description'] ?? '')),
                    'impact' => trim((string) ($narrative['impact'] ?? ($source['impact'] !== '' ? $source['impact'] : '-'))),
                    'technical_analysis' => trim((string) ($narrative['technical_analysis'] ?? ($source['technical_analysis'] !== '' ? $source['technical_analysis'] : '-'))),
                    'remediation' => trim((string) ($narrative['remediation'] ?? ($source['remediation_steps'] !== '' ? $source['remediation_steps'] : '-'))),
                ];

                if ($normalized['title'] === '' || $normalized['description'] === '') {
                    return ['ok' => false, 'error' => "Respons {$languageName} tidak lengkap untuk temuan {$findingId}.", 'status' => 502];
                }

                $byFindingId[$findingId] = $normalized;
            }

            if (count($byFindingId) !== count($batchIds)) {
                return ['ok' => false, 'error' => "Respons {$languageName} tidak mencakup seluruh temuan dalam batch.", 'status' => 502];
            }

            return ['ok' => true, 'narratives' => $byFindingId];
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => "Kesalahan saat sintesis {$languageName}: ".$e->getMessage(), 'status' => 500];
        }
    }

    /**
     * Decode LLM JSON even when wrapped in think tags, markdown fences, or prose.
     *
     * @return array<string, mixed>|null
     */
    private function decodeNarrativeJson(string $rawContent): ?array
    {
        $cleaned = preg_replace('/<think\b[^>]*>.*?<\/think>/is', '', $rawContent) ?? $rawContent;
        $trimmed = trim($cleaned);

        if (preg_match('/```(?:json)?\s*([\s\S]*?)\s*```/i', $trimmed, $fenceMatch) === 1) {
            $trimmed = trim($fenceMatch[1]);
        }

        $decoded = json_decode($trimmed, true);
        if (is_array($decoded)) {
            return $decoded;
        }

        $firstBrace = strpos($trimmed, '{');
        $lastBrace = strrpos($trimmed, '}');
        if ($firstBrace !== false && $lastBrace !== false && $lastBrace > $firstBrace) {
            $slice = substr($trimmed, $firstBrace, $lastBrace - $firstBrace + 1);
            $decodedSlice = json_decode($slice, true);
            if (is_array($decodedSlice)) {
                return $decodedSlice;
            }
        }

        return null;
    }

    private function trimNarrativeField(string $value, int $maxLength): string
    {
        $normalized = trim($value);
        if (mb_strlen($normalized) <= $maxLength) {
            return $normalized;
        }

        return rtrim(mb_substr($normalized, 0, $maxLength)).'...';
    }

    /**
     * Persist merged narratives into report_narratives.json, preserving partial progress when incremental.
     *
     * @param  list<array<string, mixed>>  $allFindings
     * @param  array<string, array<string, array<string, string>>>  $languageNarratives
     */
    private function persistSynthesisNarratives(Scan $scan, array $allFindings, array $languageNarratives, bool $mergeExisting): ?int
    {
        $narrativesPath = "pentesin_runs/web-{$scan->id}/report_narratives.json";
        $existingById = [];

        if ($mergeExisting && Storage::disk('local')->exists($narrativesPath)) {
            $existingData = json_decode((string) Storage::disk('local')->get($narrativesPath), true);
            if (is_array($existingData) && is_array($existingData['findings'] ?? null)) {
                foreach ($existingData['findings'] as $row) {
                    if (! is_array($row)) {
                        continue;
                    }
                    $id = $row['finding_id'] ?? $row['id'] ?? null;
                    if (is_string($id) && $id !== '') {
                        $existingById[$id] = $row;
                    }
                }
            }
        }

        $merged = ['findings' => []];
        foreach ($allFindings as $finding) {
            $findingId = (string) $finding['id'];
            $entry = is_array($existingById[$findingId] ?? null)
                ? $existingById[$findingId]
                : ['finding_id' => $findingId];
            $entry['finding_id'] = $findingId;

            foreach (['en', 'id'] as $langKey) {
                if (isset($languageNarratives[$langKey][$findingId])) {
                    $entry[$langKey] = $languageNarratives[$langKey][$findingId];
                }
            }

            if (isset($entry['en']) || isset($entry['id'])) {
                $merged['findings'][] = $entry;
            }
        }

        $encodedMerged = json_encode($merged, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($encodedMerged === false) {
            return null;
        }

        $saved = Storage::disk('local')->put($narrativesPath, $encodedMerged);
        if (! $saved) {
            $absPath = storage_path("app/private/{$narrativesPath}");
            $dir = dirname($absPath);
            if (! is_dir($dir)) {
                @mkdir($dir, 0775, true);
            }
            @file_put_contents($absPath, $encodedMerged);
            $saved = Storage::disk('local')->exists($narrativesPath);
        }
        if (! $saved) {
            return null;
        }

        $artifacts = $scan->artifacts ?? [];
        if (! in_array('report_narratives.json', $artifacts, true)) {
            $scan->update(['artifacts' => array_values(array_unique([...$artifacts, 'report_narratives.json']))]);
        }

        return count($merged['findings']);
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
            'noise_profile' => ['sometimes', Rule::in(['off', 'quiet', 'balanced', 'aggressive'])],
            'auth_credentials_raw' => ['nullable', 'string', 'max:10000'],
            'context_mode' => ['sometimes', 'accepted'],
            'smart_recon' => ['sometimes', 'accepted'],
            'llm_profile_id' => ['required', 'integer', 'exists:llm_profiles,id'],
            'max_budget' => ['nullable', 'numeric', 'min:0.01', 'max:1000'],
        ]);
        $profile = LlmProfile::where('user_id', $request->user()->id)->findOrFail($data['llm_profile_id']);
        $integration = IntegrationSetting::where('user_id', $request->user()->id)->first();
        $mode = $data['mode'] === 'quick' ? 'standard' : $data['mode'];
        $authCredentials = array_values(array_slice(array_filter(
            array_map('trim', preg_split('/\r?\n/', (string) ($data['auth_credentials_raw'] ?? '')) ?: []),
            fn (string $line): bool => $line !== ''
        ), 0, 10));
        $scan = Scan::create([
            'user_id' => $request->user()->id, 'target' => $data['target'], 'instruction' => $data['instruction'] ?? '',
            'mode' => $mode, 'noise_profile' => $data['noise_profile'] ?? 'off', 'auth_credentials' => $authCredentials ?: null,
            'integration_snapshot' => $integration?->runnerPayload(),
            'context_mode' => (bool) ($data['context_mode'] ?? false), 'smart_recon' => (bool) ($data['smart_recon'] ?? false), 'kind' => 'scan', 'status' => 'queued', 'llm_profile_id' => $profile->id,
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
            'scan' => $scan->only(['id', 'target', 'instruction', 'status', 'phase', 'error', 'test_result', 'started_at', 'finished_at', 'artifacts', 'total_tokens', 'llm_usage']) + ['artifacts' => array_intersect($scan->artifacts ?? [], ['penetration_test_report.md', 'vulnerabilities.json', 'findings.sarif', 'coverage.json'])],
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
        abort_unless(in_array($name, ['penetration_test_report.md', 'vulnerabilities.json', 'findings.sarif', 'coverage.json', 'report_narratives.json'], true), 404);
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
        abort_unless(in_array($name, ['penetration_test_report.md', 'vulnerabilities.json', 'findings.sarif', 'coverage.json', 'report_narratives.json'], true) && in_array($name, $scan->artifacts ?? [], true), 404);
        $path = "pentesin_runs/web-{$scan->id}/{$name}";
        abort_unless(Storage::disk('local')->exists($path), 404);

        return Storage::disk('local')->download($path, $name, ['Cache-Control' => 'private, no-store']);
    }

    private function expireOwnerLeases(): void
    {
        Scan::where('user_id', auth()->id())->where('status', 'running')->where('lease_expires_at', '<', now())->update(['status' => 'interrupted', 'error' => 'Runner terputus; periksa proses runner sebelum menjalankan ulang.', 'finished_at' => now()]);
    }
}
