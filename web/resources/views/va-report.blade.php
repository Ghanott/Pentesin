@php
    $isEn = ($lang ?? 'id') === 'en';
    $reportId = 'VA-' . strtoupper(substr(md5((string) $scan->id . ($scan->target ?? '')), 0, 8));
    $parsedHost = parse_url($scan->target ?? '', PHP_URL_HOST) ?: ($scan->target ?? 'Unknown Target');
    $scopeTargets = is_array($coverage['scope']['targets'] ?? null) && ! empty($coverage['scope']['targets'])
        ? implode(', ', array_filter($coverage['scope']['targets'], 'is_string'))
        : ($scan->target ?? '—');

    $started = $scan->started_at ?? $scan->created_at;
    $finished = $scan->finished_at;
    $durationStr = '—';
    if ($started && $finished) {
        $secs = max(1, (int) $started->diffInSeconds($finished));
        $mins = intdiv($secs, 60);
        $rem = $secs % 60;
        $durationStr = $mins > 0 ? "{$mins}m {$rem}s" : "{$rem}s";
    }

    $sevCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
    foreach ($findings as $f) {
        $s = strtolower((string) ($f['severity'] ?? 'info'));
        if (array_key_exists($s, $sevCounts)) {
            $sevCounts[$s]++;
        }
    }

    $totalTested = max(0, (int) ($outcomes['total_tested'] ?? count($entries)));
    $safeTotal = max(0, (int) ($outcomes['safe_total'] ?? 0));
    $reportedTotal = max(0, (int) ($outcomes['reported'] ?? 0));
    $followUpTotal = max(0, (int) ($outcomes['needs_follow_up'] ?? 0));
    $gapCount = count($gaps ?? []);
    $isComplete = (bool) ($completeness['complete'] ?? false);
    $caveats = is_array($completeness['caveats'] ?? null) ? array_values(array_filter($completeness['caveats'], 'is_string')) : [];

    $pct = fn (int $n): float => $totalTested > 0 ? round(($n / $totalTested) * 100, 1) : 0.0;

    if ($reportedTotal > 0 || count($findings) > 0) {
        $postureClass = 'posture-vuln';
        $postureTitle = $isEn
            ? 'Vulnerabilities Identified Within Tested Scope'
            : 'Kerentanan Teridentifikasi pada Cakupan Pengujian';
        $postureDesc = $isEn
            ? "{$reportedTotal} tested security check(s) confirmed exploitable or reportable issues, while {$safeTotal} check(s) passed verification with no issue found or ruled out."
            : "{$reportedTotal} pengujian keamanan mengonfirmasi adanya temuan kerentanan, sementara {$safeTotal} pengujian terverifikasi aman (tidak ditemukan celah atau telah dieliminasi).";
    } elseif ($followUpTotal > 0 || $gapCount > 0 || ! $isComplete) {
        $postureClass = 'posture-partial';
        $postureTitle = $isEn
            ? 'Assessment Partially Verified — Follow-Up Required'
            : 'Asesmen Terverifikasi Sebagian — Perlu Tindak Lanjut';
        $postureDesc = $isEn
            ? "No exploitable vulnerabilities were confirmed in completed checks ({$safeTotal} safe), however {$followUpTotal} check(s) require follow-up and {$gapCount} coverage gap(s) remain."
            : "Belum ditemukan kerentanan yang dapat dieksploitasi pada pengujian selesai ({$safeTotal} aman), namun terdapat {$followUpTotal} area perlu tindak lanjut dan {$gapCount} kesenjangan cakupan.";
    } else {
        $postureClass = 'posture-safe';
        $postureTitle = $isEn
            ? 'Verified Safe Across Assessed Scope'
            : 'Terverifikasi Aman pada Seluruh Cakupan Diuji';
        $postureDesc = $isEn
            ? "All {$safeTotal} security checks across assessed surfaces completed without reportable vulnerabilities."
            : "Seluruh {$safeTotal} pengujian keamanan pada permukaan yang diperiksa selesai tanpa temuan kerentanan yang dapat dieksploitasi.";
    }

    $outcomeMeta = function (string $outcome) use ($isEn): array {
        return match ($outcome) {
            'reported' => [
                'label' => $isEn ? 'VULNERABLE' : 'RENTAN',
                'sub' => $isEn ? 'Reported' : 'Dilaporkan',
                'badge' => 'badge-vuln',
                'row' => 'row-vuln',
                'group' => 'vuln',
            ],
            'no_issue_found' => [
                'label' => $isEn ? 'SAFE · NO ISSUE' : 'AMAN · BERSIH',
                'sub' => $isEn ? 'Verified Safe' : 'Tidak Ada Celah',
                'badge' => 'badge-safe',
                'row' => 'row-safe',
                'group' => 'safe',
            ],
            'ruled_out' => [
                'label' => $isEn ? 'SAFE · RULED OUT' : 'AMAN · DIELIMINASI',
                'sub' => $isEn ? 'False Positive / Mitigated' : 'Bukan Kerentanan',
                'badge' => 'badge-safe',
                'row' => 'row-safe',
                'group' => 'safe',
            ],
            'not_applicable' => [
                'label' => $isEn ? 'N/A' : 'TIDAK BERLAKU',
                'sub' => $isEn ? 'Not Applicable' : 'Tidak Relevan',
                'badge' => 'badge-na',
                'row' => 'row-na',
                'group' => 'other',
            ],
            'needs_follow_up' => [
                'label' => $isEn ? 'FOLLOW-UP' : 'TINDAK LANJUT',
                'sub' => $isEn ? 'Needs Manual / Deeper Check' : 'Perlu Pemeriksaan Lanjut',
                'badge' => 'badge-followup',
                'row' => 'row-followup',
                'group' => 'other',
            ],
            default => [
                'label' => strtoupper($outcome ?: 'UNKNOWN'),
                'sub' => '',
                'badge' => 'badge-na',
                'row' => 'row-na',
                'group' => 'other',
            ],
        };
    };
@endphp
<!DOCTYPE html>
<html lang="{{ $isEn ? 'en' : 'id' }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $isEn ? 'Vulnerability Assessment Report' : 'Laporan Vulnerability Assessment' }} · {{ $parsedHost }}</title>
    <link rel="preconnect" href="https://fonts.bunny.net">
    <link href="https://fonts.bunny.net/css?family=poppins:400,500,600,700|jetbrains-mono:400,500,600&display=swap" rel="stylesheet" />
    <style>
        :root {
            --font-sans: 'Poppins', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
            --c-ink: #0f172a;
            --c-muted: #475569;
            --c-subtle: #64748b;
            --c-border: #e2e8f0;
            --c-bg: #f8fafc;
            --c-surface: #ffffff;
            --c-accent: #0284c7;
            --c-safe: #059669;
            --c-safe-bg: #ecfdf5;
            --c-safe-border: #a7f3d0;
            --c-vuln: #dc2626;
            --c-vuln-bg: #fef2f2;
            --c-vuln-border: #fecaca;
            --c-warn: #d97706;
            --c-warn-bg: #fffbeb;
            --c-warn-border: #fde68a;
            --c-na: #475569;
            --c-na-bg: #f1f5f9;
            --c-na-border: #cbd5e1;
        }

        *, *::before, *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-sans);
            color: var(--c-ink);
            background: #0f172a;
            font-size: 13px;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }

        /* Interactive Sticky Toolbar */
        .report-toolbar {
            position: sticky;
            top: 0;
            z-index: 1000;
            background: #0b1118;
            border-bottom: 1px solid #1e293b;
            padding: 12px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }

        .toolbar-left, .toolbar-right {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .btn-toolbar {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            height: 36px;
            padding: 0 14px;
            border-radius: 8px;
            font-size: 12.5px;
            font-weight: 500;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.15s ease;
            border: 1px solid transparent;
            font-family: var(--font-sans);
        }

        .btn-toolbar-back {
            background: #172330;
            color: #94a3b8;
            border-color: #273442;
        }
        .btn-toolbar-back:hover {
            color: #ffffff;
            background: #203042;
        }

        .btn-toolbar-secondary {
            background: #132235;
            color: #7dd3fc;
            border-color: #1e3a5f;
        }
        .btn-toolbar-secondary:hover {
            background: #1b314d;
            color: #ffffff;
        }

        .btn-toolbar-print {
            background: #38bdf8;
            color: #082f49;
            font-weight: 600;
        }
        .btn-toolbar-print:hover {
            background: #7dd3fc;
            box-shadow: 0 0 16px rgba(56, 189, 248, 0.35);
        }

        .lang-switch {
            display: inline-flex;
            background: #131d28;
            border: 1px solid #273442;
            border-radius: 8px;
            padding: 2px;
        }
        .lang-switch a {
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 500;
            color: #8da1b5;
            text-decoration: none;
        }
        .lang-switch a.active {
            background: #1e2d3d;
            color: #ffffff;
            font-weight: 600;
        }
        .lang-switch a:hover:not(.active) {
            color: #ffffff;
        }

        /* Document Container */
        .report-page-wrapper {
            max-width: 960px;
            margin: 28px auto 60px;
            background: var(--c-surface);
            border-radius: 12px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.55);
            overflow: hidden;
        }

        .report-section {
            padding: 38px 46px;
        }

        .report-section + .report-section {
            border-top: 1px solid var(--c-border);
        }

        /* Cover Header */
        .va-header {
            background: linear-gradient(135deg, #0b1322 0%, #101f36 100%);
            color: #f8fafc;
            padding: 40px 46px 34px;
            border-bottom: 4px solid #38bdf8;
        }

        .va-header-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }

        .brand-mark {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 700;
            font-size: 14px;
            letter-spacing: 0.04em;
            color: #ffffff;
        }

        .brand-mark span.accent {
            color: #38bdf8;
        }

        .classification-pill {
            font-family: var(--font-mono);
            font-size: 10.5px;
            font-weight: 600;
            letter-spacing: 0.08em;
            color: #7dd3fc;
            background: rgba(56, 189, 248, 0.12);
            border: 1px solid rgba(56, 189, 248, 0.32);
            padding: 4px 10px;
            border-radius: 999px;
            text-transform: uppercase;
        }

        .va-doc-subtitle {
            font-family: var(--font-mono);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            color: #38bdf8;
            margin-bottom: 8px;
        }

        .va-doc-title {
            font-size: 27px;
            font-weight: 700;
            line-height: 1.25;
            color: #ffffff;
            margin-bottom: 8px;
        }

        .va-doc-target {
            font-family: var(--font-mono);
            font-size: 13px;
            color: #cbd5e1;
            word-break: break-all;
            margin-bottom: 26px;
        }

        .meta-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }

        .meta-cell {
            background: rgba(15, 23, 42, 0.55);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 8px;
            padding: 10px 12px;
        }

        .meta-label {
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #94a3b8;
            margin-bottom: 3px;
        }

        .meta-value {
            font-family: var(--font-mono);
            font-size: 12px;
            font-weight: 600;
            color: #f8fafc;
            word-break: break-word;
        }

        /* Section Titles */
        .section-heading {
            display: flex;
            align-items: baseline;
            justify-content: space-between;
            gap: 12px;
            border-bottom: 2px solid var(--c-ink);
            padding-bottom: 10px;
            margin-bottom: 22px;
        }

        .section-heading h2 {
            font-size: 17px;
            font-weight: 700;
            color: var(--c-ink);
            letter-spacing: -0.01em;
        }

        .section-code {
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 600;
            color: var(--c-accent);
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        /* Posture Banner */
        .posture-banner {
            border-radius: 10px;
            padding: 18px 22px;
            border: 1px solid;
            margin-bottom: 22px;
            display: flex;
            align-items: flex-start;
            gap: 14px;
            break-inside: avoid;
        }

        .posture-vuln {
            background: #fef2f2;
            border-color: #fecaca;
            color: #7f1d1d;
        }

        .posture-partial {
            background: #fffbeb;
            border-color: #fde68a;
            color: #78350f;
        }

        .posture-safe {
            background: #ecfdf5;
            border-color: #a7f3d0;
            color: #064e3b;
        }

        .posture-icon {
            width: 34px;
            height: 34px;
            border-radius: 8px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            margin-top: 2px;
        }

        .posture-vuln .posture-icon { background: #fee2e2; color: #dc2626; }
        .posture-partial .posture-icon { background: #fef3c7; color: #d97706; }
        .posture-safe .posture-icon { background: #d1fae5; color: #059669; }

        .posture-banner h3 {
            font-size: 15px;
            font-weight: 700;
            margin-bottom: 4px;
        }

        .posture-banner p {
            font-size: 12.5px;
            line-height: 1.55;
            opacity: 0.92;
        }

        /* KPI Cards */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 14px;
            margin-bottom: 20px;
        }

        .kpi-card {
            border: 1px solid var(--c-border);
            border-radius: 10px;
            padding: 14px 16px;
            background: var(--c-bg);
            border-top: 3px solid #64748b;
            break-inside: avoid;
        }

        .kpi-card.is-total { border-top-color: #0284c7; }
        .kpi-card.is-safe { border-top-color: #059669; background: #f0fdf4; border-color: #bbf7d0; }
        .kpi-card.is-vuln { border-top-color: #dc2626; background: #fef2f2; border-color: #fecaca; }
        .kpi-card.is-warn { border-top-color: #d97706; background: #fffbeb; border-color: #fde68a; }

        .kpi-num {
            font-family: var(--font-mono);
            font-size: 26px;
            font-weight: 700;
            line-height: 1.15;
            color: var(--c-ink);
        }

        .kpi-card.is-safe .kpi-num { color: #047857; }
        .kpi-card.is-vuln .kpi-num { color: #b91c1c; }
        .kpi-card.is-warn .kpi-num { color: #b45309; }

        .kpi-label {
            font-size: 11.5px;
            font-weight: 600;
            color: var(--c-ink);
            margin-top: 4px;
        }

        .kpi-sub {
            font-size: 11px;
            color: var(--c-subtle);
            margin-top: 2px;
        }

        /* Distribution Bar */
        .dist-card {
            border: 1px solid var(--c-border);
            border-radius: 10px;
            padding: 14px 18px;
            background: #ffffff;
            margin-bottom: 18px;
            break-inside: avoid;
        }

        .dist-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 12px;
            font-weight: 600;
            color: var(--c-muted);
            margin-bottom: 10px;
        }

        .dist-bar {
            height: 10px;
            border-radius: 999px;
            background: #e2e8f0;
            overflow: hidden;
            display: flex;
            margin-bottom: 10px;
        }

        .dist-seg-safe { background: #10b981; }
        .dist-seg-vuln { background: #ef4444; }
        .dist-seg-follow { background: #f59e0b; }
        .dist-seg-na { background: #94a3b8; }

        .dist-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            font-size: 11px;
            color: var(--c-muted);
        }

        .dist-legend-item {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
        }

        /* Notice / Caveats */
        .notice-box {
            border: 1px solid #cbd5e1;
            background: #f8fafc;
            border-left: 4px solid #0284c7;
            border-radius: 6px;
            padding: 12px 16px;
            font-size: 12px;
            color: var(--c-muted);
        }

        .notice-box.is-warn {
            background: #fffbeb;
            border-color: #fde68a;
            border-left-color: #d97706;
            color: #78350f;
        }

        .notice-box ul {
            margin-top: 6px;
            padding-left: 18px;
        }

        /* Interactive Filter Bar (Screen Only) */
        .matrix-controls {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 14px;
            background: #f8fafc;
            border: 1px solid var(--c-border);
            padding: 10px 12px;
            border-radius: 8px;
        }

        .filter-pills {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }

        .filter-pill {
            border: 1px solid var(--c-border);
            background: #ffffff;
            color: var(--c-muted);
            font-family: var(--font-sans);
            font-size: 11.5px;
            font-weight: 500;
            padding: 5px 11px;
            border-radius: 999px;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .filter-pill.active {
            background: #0f172a;
            color: #ffffff;
            border-color: #0f172a;
        }

        .matrix-search {
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            padding: 5px 10px;
            font-size: 12px;
            font-family: var(--font-sans);
            min-width: 220px;
            color: var(--c-ink);
        }

        /* Assessment Tables */
        .va-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            border: 1px solid var(--c-border);
        }

        .va-table thead th {
            background: #0f172a;
            color: #f8fafc;
            text-align: left;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            padding: 10px 12px;
            border-bottom: 2px solid #1e293b;
        }

        .va-table tbody td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--c-border);
            vertical-align: top;
            color: var(--c-ink);
        }

        .va-table tbody tr:last-child td {
            border-bottom: none;
        }

        .va-table tbody tr {
            break-inside: avoid;
        }

        .va-table tbody tr.row-vuln {
            background: #fffafa;
        }

        .va-table tbody tr.row-safe {
            background: #ffffff;
        }

        .va-table tbody tr.row-followup {
            background: #fffdf5;
        }

        .va-table tbody tr.row-na {
            background: #f8fafc;
        }

        .surface-name {
            font-family: var(--font-mono);
            font-size: 11.5px;
            font-weight: 600;
            color: #0f172a;
            word-break: break-word;
            margin-bottom: 3px;
        }

        .risk-area {
            font-size: 11.5px;
            color: var(--c-muted);
            font-weight: 500;
        }

        .outcome-badge {
            display: inline-block;
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.04em;
            padding: 3px 8px;
            border-radius: 6px;
            border: 1px solid;
            white-space: nowrap;
        }

        .badge-vuln { background: var(--c-vuln-bg); color: var(--c-vuln); border-color: var(--c-vuln-border); }
        .badge-safe { background: var(--c-safe-bg); color: var(--c-safe); border-color: var(--c-safe-border); }
        .badge-followup { background: var(--c-warn-bg); color: var(--c-warn); border-color: var(--c-warn-border); }
        .badge-na { background: var(--c-na-bg); color: var(--c-na); border-color: var(--c-na-border); }

        .outcome-sub {
            font-size: 10.5px;
            color: var(--c-subtle);
            margin-top: 3px;
        }

        .evidence-text {
            font-size: 11.5px;
            color: var(--c-muted);
            line-height: 1.5;
            word-break: break-word;
        }

        .history-chip {
            margin-top: 5px;
            font-family: var(--font-mono);
            font-size: 10px;
            color: var(--c-subtle);
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            display: inline-block;
        }

        .agent-cell {
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--c-muted);
            white-space: nowrap;
        }

        .source-tag {
            display: block;
            font-size: 10px;
            color: var(--c-subtle);
            margin-top: 2px;
        }

        /* Severity Pills */
        .sev-pill {
            display: inline-block;
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            padding: 2px 7px;
            border-radius: 5px;
            color: #ffffff;
        }
        .sev-critical { background: #dc2626; }
        .sev-high { background: #ea580c; }
        .sev-medium { background: #d97706; }
        .sev-low { background: #2563eb; }
        .sev-info { background: #64748b; }

        .skill-list {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-bottom: 18px;
        }

        .skill-chip {
            font-family: var(--font-mono);
            font-size: 11px;
            background: #f1f5f9;
            border: 1px solid #cbd5e1;
            color: #334155;
            padding: 3px 9px;
            border-radius: 6px;
        }

        .two-col-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 18px;
        }

        .disclaimer-card {
            background: #f8fafc;
            border: 1px solid var(--c-border);
            border-radius: 8px;
            padding: 18px 22px;
            font-size: 11.5px;
            line-height: 1.65;
            color: var(--c-subtle);
            break-inside: avoid;
        }

        .disclaimer-card strong {
            color: var(--c-ink);
        }

        @media (max-width: 780px) {
            .meta-grid, .kpi-grid, .two-col-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .report-section, .va-header {
                padding: 24px 20px;
            }
        }

        @media print {
            @page {
                size: A4;
                margin: 14mm 12mm;
            }

            body {
                background: #ffffff;
                font-size: 11px;
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
            }

            .no-print {
                display: none !important;
            }

            .report-page-wrapper {
                margin: 0;
                max-width: none;
                box-shadow: none;
                border-radius: 0;
            }

            .report-section {
                padding: 22px 16px;
            }

            .va-header {
                padding: 24px 22px;
            }

            .va-table tbody tr {
                display: table-row !important;
            }
        }
    </style>
</head>
<body>
    <div class="report-toolbar no-print">
        <div class="toolbar-left">
            <a class="btn-toolbar btn-toolbar-back" href="{{ route('scans.show', $scan) }}">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
                <span>{{ $isEn ? 'Back to Scan' : 'Kembali ke Scan' }}</span>
            </a>
            <a class="btn-toolbar btn-toolbar-secondary" href="{{ route('scans.report', ['scan' => $scan, 'lang' => $lang]) }}">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                <span>{{ $isEn ? 'Pentest Report PDF' : 'Laporan Pentest PDF' }}</span>
            </a>
        </div>
        <div class="toolbar-right">
            <div class="lang-switch" aria-label="Language toggle">
                <a href="{{ route('scans.va-report', ['scan' => $scan, 'lang' => 'id']) }}" class="{{ ! $isEn ? 'active' : '' }}">ID</a>
                <a href="{{ route('scans.va-report', ['scan' => $scan, 'lang' => 'en']) }}" class="{{ $isEn ? 'active' : '' }}">EN</a>
            </div>
            <button type="button" class="btn-toolbar btn-toolbar-print" onclick="window.print()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
                <span>{{ $isEn ? 'Print / Save VA PDF' : 'Cetak / Simpan VA PDF' }}</span>
            </button>
        </div>
    </div>

    <div class="report-page-wrapper">
        {{-- Header / Classification Banner --}}
        <header class="va-header">
            <div class="va-header-top">
                <div class="brand-mark">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>
                    <span>PENTESIN <span class="accent">VA REPORT</span></span>
                </div>
                <span class="classification-pill">{{ $isEn ? 'CONFIDENTIAL · VULNERABILITY ASSESSMENT' : 'RAHASIA · EVALUASI KERENTANAN (VA)' }}</span>
            </div>

            <div class="va-doc-subtitle">{{ $isEn ? 'Surface Verification & Security Assessment Ledger' : 'Matriks Verifikasi Permukaan & Evaluasi Keamanan' }}</div>
            <h1 class="va-doc-title">{{ $isEn ? 'Vulnerability Assessment Report' : 'Laporan Vulnerability Assessment' }}</h1>
            <div class="va-doc-target">{{ $scopeTargets }}</div>

            <div class="meta-grid">
                <div class="meta-cell">
                    <div class="meta-label">{{ $isEn ? 'Document ID' : 'ID Dokumen' }}</div>
                    <div class="meta-value">{{ $reportId }}</div>
                </div>
                <div class="meta-cell">
                    <div class="meta-label">{{ $isEn ? 'Scan Mode / Status' : 'Mode / Status Scan' }}</div>
                    <div class="meta-value">{{ strtoupper((string) ($scan->mode ?? 'standard')) }} · {{ strtoupper((string) ($scan->status ?? 'unknown')) }}</div>
                </div>
                <div class="meta-cell">
                    <div class="meta-label">{{ $isEn ? 'Assessed Date / Duration' : 'Tanggal / Durasi' }}</div>
                    <div class="meta-value">{{ $started?->format('d M Y H:i') ?? '—' }} ({{ $durationStr }})</div>
                </div>
                <div class="meta-cell">
                    <div class="meta-label">{{ $isEn ? 'Telemetry Source' : 'Sumber Data Uji' }}</div>
                    <div class="meta-value">{{ $hasCoverageData ? ($isEn ? 'Verified Coverage Ledger' : 'Ledger Pengujian Resmi') : ($isEn ? 'Legacy Findings Fallback' : 'Fallback Temuan Lama') }}</div>
                </div>
            </div>
        </header>

        {{-- Section 1: Executive VA Summary --}}
        <section class="report-section">
            <div class="section-heading">
                <h2>{{ $isEn ? '1. Executive Assessment Summary & Coverage Posture' : '1. Ringkasan Eksekutif & Cakupan Pengujian' }}</h2>
                <span class="section-code">SEC-01 // POSTURE</span>
            </div>

            <div class="posture-banner {{ $postureClass }}">
                <span class="posture-icon" aria-hidden="true">
                    @if($postureClass === 'posture-vuln')
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                    @elseif($postureClass === 'posture-partial')
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    @else
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>
                    @endif
                </span>
                <div>
                    <h3>{{ $postureTitle }}</h3>
                    <p>{{ $postureDesc }}</p>
                </div>
            </div>

            <div class="kpi-grid">
                <div class="kpi-card is-total">
                    <div class="kpi-num">{{ $totalTested }}</div>
                    <div class="kpi-label">{{ $isEn ? 'Surfaces / Checks Tested' : 'Total Area / Skenario Diuji' }}</div>
                    <div class="kpi-sub">{{ $isEn ? '100% of recorded VA checks' : 'Seluruh cakupan VA tercatat' }}</div>
                </div>
                <div class="kpi-card is-safe">
                    <div class="kpi-num">{{ $safeTotal }}</div>
                    <div class="kpi-label">{{ $isEn ? 'Verified Safe / Clean' : 'Aman / Terverifikasi Bersih' }}</div>
                    <div class="kpi-sub">{{ $outcomes['no_issue_found'] }} {{ $isEn ? 'no issue' : 'bersih' }} · {{ $outcomes['ruled_out'] }} {{ $isEn ? 'ruled out' : 'dieliminasi' }} · {{ $outcomes['not_applicable'] }} N/A</div>
                </div>
                <div class="kpi-card is-vuln">
                    <div class="kpi-num">{{ $reportedTotal }}</div>
                    <div class="kpi-label">{{ $isEn ? 'Vulnerable / Reported' : 'Rentan / Temuan Dilaporkan' }}</div>
                    <div class="kpi-sub">{{ count($findings) }} {{ $isEn ? 'confirmed finding(s)' : 'temuan terkonfirmasi' }}</div>
                </div>
                <div class="kpi-card is-warn">
                    <div class="kpi-num">{{ $followUpTotal + $gapCount }}</div>
                    <div class="kpi-label">{{ $isEn ? 'Follow-Up & Gaps' : 'Tindak Lanjut & Gap' }}</div>
                    <div class="kpi-sub">{{ $followUpTotal }} {{ $isEn ? 'follow-up' : 'tindak lanjut' }} · {{ $gapCount }} {{ $isEn ? 'gaps' : 'gap' }}</div>
                </div>
            </div>

            @if($totalTested > 0)
                <div class="dist-card">
                    <div class="dist-header">
                        <span>{{ $isEn ? 'Verification Outcome Breakdown' : 'Distribusi Hasil Pengujian Keamanan' }}</span>
                        <span>{{ $isEn ? 'Safe Rate' : 'Rasio Aman' }}: {{ $pct($safeTotal) }}%</span>
                    </div>
                    <div class="dist-bar" aria-hidden="true">
                        @if($outcomes['reported'] > 0)
                            <div class="dist-seg-vuln" style="width: {{ $pct($outcomes['reported']) }}%"></div>
                        @endif
                        @if(($outcomes['no_issue_found'] + $outcomes['ruled_out']) > 0)
                            <div class="dist-seg-safe" style="width: {{ $pct($outcomes['no_issue_found'] + $outcomes['ruled_out']) }}%"></div>
                        @endif
                        @if($outcomes['needs_follow_up'] > 0)
                            <div class="dist-seg-follow" style="width: {{ $pct($outcomes['needs_follow_up']) }}%"></div>
                        @endif
                        @if($outcomes['not_applicable'] > 0)
                            <div class="dist-seg-na" style="width: {{ $pct($outcomes['not_applicable']) }}%"></div>
                        @endif
                    </div>
                    <div class="dist-legend">
                        <span class="dist-legend-item"><i class="dot" style="background:#ef4444"></i> {{ $isEn ? 'Vulnerable' : 'Rentan' }}: {{ $outcomes['reported'] }} ({{ $pct($outcomes['reported']) }}%)</span>
                        <span class="dist-legend-item"><i class="dot" style="background:#10b981"></i> {{ $isEn ? 'Safe (No Issue + Ruled Out)' : 'Aman (Bersih + Dieliminasi)' }}: {{ $outcomes['no_issue_found'] + $outcomes['ruled_out'] }} ({{ $pct($outcomes['no_issue_found'] + $outcomes['ruled_out']) }}%)</span>
                        <span class="dist-legend-item"><i class="dot" style="background:#f59e0b"></i> {{ $isEn ? 'Needs Follow-Up' : 'Perlu Tindak Lanjut' }}: {{ $outcomes['needs_follow_up'] }} ({{ $pct($outcomes['needs_follow_up']) }}%)</span>
                        <span class="dist-legend-item"><i class="dot" style="background:#94a3b8"></i> N/A: {{ $outcomes['not_applicable'] }} ({{ $pct($outcomes['not_applicable']) }}%)</span>
                    </div>
                </div>
            @endif

            @if(! $hasCoverageData)
                <div class="notice-box is-warn">
                    <strong>{{ $isEn ? 'Legacy Scan Notice:' : 'Catatan Data Scan Lama:' }}</strong>
                    {{ $isEn
                        ? 'This scan did not produce a coverage.json ledger. Only reported findings are available below; negative/safe surface checks were not separately logged for this run.'
                        : 'Pemindaian ini belum memiliki file coverage.json. Hanya temuan kerentanan yang tercatat; hasil pemeriksaan bagian yang aman belum terekam terpisah pada run ini.' }}
                </div>
            @elseif(! empty($caveats) || ! $isComplete)
                <div class="notice-box is-warn">
                    <strong>{{ $isEn ? 'Assessment Completeness Caveats:' : 'Catatan Kelengkapan Pengujian:' }}</strong>
                    @if(! empty($completeness['exit_reason']))
                        <span>({{ $completeness['exit_reason'] }})</span>
                    @endif
                    @if(! empty($caveats))
                        <ul>
                            @foreach($caveats as $caveat)
                                <li>{{ $caveat }}</li>
                            @endforeach
                        </ul>
                    @endif
                </div>
            @endif
        </section>

        {{-- Section 2: Surface-by-Surface VA Matrix --}}
        <section class="report-section">
            <div class="section-heading">
                <h2>{{ $isEn ? '2. Vulnerability Assessment Matrix (Tested Areas & Outcomes)' : '2. Matriks Vulnerability Assessment (Bagian Diuji & Hasilnya)' }}</h2>
                <span class="section-code">SEC-02 // MATRIX</span>
            </div>

            @if(! empty($entries))
                <div class="matrix-controls no-print">
                    <div class="filter-pills" id="va-filter-pills">
                        <button type="button" class="filter-pill active" data-filter="all">{{ $isEn ? 'All' : 'Semua' }} ({{ count($entries) }})</button>
                        <button type="button" class="filter-pill" data-filter="vuln">{{ $isEn ? 'Vulnerable' : 'Rentan' }} ({{ $outcomes['reported'] }})</button>
                        <button type="button" class="filter-pill" data-filter="safe">{{ $isEn ? 'Safe' : 'Aman' }} ({{ $outcomes['no_issue_found'] + $outcomes['ruled_out'] }})</button>
                        <button type="button" class="filter-pill" data-filter="other">{{ $isEn ? 'Follow-Up / N/A' : 'Tindak Lanjut / N/A' }} ({{ $followUpTotal + $outcomes['not_applicable'] }})</button>
                    </div>
                    <input type="search" id="va-matrix-search" class="matrix-search" placeholder="{{ $isEn ? 'Filter surface or risk class...' : 'Cari endpoint atau jenis uji...' }}">
                </div>

                <table class="va-table" id="va-matrix-table">
                    <thead>
                        <tr>
                            <th style="width:36px">#</th>
                            <th style="width:27%">{{ $isEn ? 'Tested Surface & Risk Area' : 'Area / Endpoint & Kelas Risiko' }}</th>
                            <th style="width:16%">{{ $isEn ? 'Assessment Result' : 'Status Hasil' }}</th>
                            <th>{{ $isEn ? 'Verification Evidence & Notes' : 'Bukti / Catatan Pengujian' }}</th>
                            <th style="width:15%">{{ $isEn ? 'Verified By' : 'Diverifikasi Oleh' }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($entries as $idx => $entry)
                            @php
                                $outcome = (string) ($entry['outcome'] ?? 'unknown');
                                $meta = $outcomeMeta($outcome);
                                $prevOutcomes = is_array($entry['previous_outcomes'] ?? null) ? array_filter($entry['previous_outcomes'], 'is_string') : [];
                            @endphp
                            <tr class="{{ $meta['row'] }}" data-group="{{ $meta['group'] }}" data-search="{{ strtolower((string) ($entry['surface'] ?? '') . ' ' . (string) ($entry['risk_area'] ?? '') . ' ' . (string) ($entry['evidence'] ?? '')) }}">
                                <td style="font-family:var(--font-mono);color:var(--c-subtle)">{{ $idx + 1 }}</td>
                                <td>
                                    <div class="surface-name">{{ $entry['surface'] ?? '—' }}</div>
                                    <div class="risk-area">{{ $entry['risk_area'] ?? 'General Security Check' }}</div>
                                </td>
                                <td>
                                    <span class="outcome-badge {{ $meta['badge'] }}">{{ $meta['label'] }}</span>
                                    @if($meta['sub'] !== '')
                                        <div class="outcome-sub">{{ $meta['sub'] }}</div>
                                    @endif
                                </td>
                                <td>
                                    <div class="evidence-text">{{ trim((string) ($entry['evidence'] ?? '')) !== '' ? $entry['evidence'] : ($isEn ? 'No extra note recorded.' : 'Tidak ada catatan tambahan.') }}</div>
                                    @if(! empty($prevOutcomes))
                                        <div class="history-chip">{{ $isEn ? 'History:' : 'Riwayat:' }} {{ implode(' -> ', $prevOutcomes) }} -> {{ $outcome }}</div>
                                    @endif
                                </td>
                                <td class="agent-cell">
                                    {{ $entry['recorded_by'] ?? 'Pentesin' }}
                                    <span class="source-tag">{{ $entry['source'] ?? 'coverage' }}</span>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            @else
                <div class="notice-box">
                    {{ $isEn
                        ? 'No surface coverage entries were recorded for this scan.'
                        : 'Belum ada entri cakupan permukaan yang tercatat pada pemindaian ini.' }}
                </div>
            @endif
        </section>

        {{-- Section 3: Confirmed Findings Index --}}
        <section class="report-section">
            <div class="section-heading">
                <h2>{{ $isEn ? '3. Confirmed Findings Index & Pentest Report Reference' : '3. Daftar Temuan Terkonfirmasi & Referensi Laporan Pentest' }}</h2>
                <span class="section-code">SEC-03 // FINDINGS</span>
            </div>

            @if(! empty($findings))
                <p style="font-size:12px;color:var(--c-muted);margin-bottom:14px;">
                    {{ $isEn
                        ? 'Summary of confirmed vulnerabilities mapped during assessment. For full Proof-of-Concept payloads, HTTP request/response transcripts, and step-by-step remediation guidance, refer to the companion Pentest Report PDF.'
                        : 'Ringkasan kerentanan terkonfirmasi pada pemindaian ini. Untuk rincian Proof-of-Concept, transkrip payload HTTP, dan panduan remediasi teknis lengkap, silakan buka Laporan Pentest PDF.' }}
                </p>
                <table class="va-table">
                    <thead>
                        <tr>
                            <th style="width:95px">{{ $isEn ? 'Severity' : 'Keparahan' }}</th>
                            <th style="width:110px">ID / CWE</th>
                            <th>{{ $isEn ? 'Vulnerability Title & Affected Endpoint' : 'Judul Kerentanan & Endpoint Terdampak' }}</th>
                            <th style="width:110px">{{ $isEn ? 'CVSS / Validation' : 'CVSS / Validasi' }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($findings as $f)
                            @php
                                $sev = strtolower((string) ($f['severity'] ?? 'info'));
                                if (! in_array($sev, ['critical', 'high', 'medium', 'low', 'info'], true)) {
                                    $sev = 'info';
                                }
                            @endphp
                            <tr>
                                <td><span class="sev-pill sev-{{ $sev }}">{{ strtoupper($sev) }}</span></td>
                                <td class="agent-cell">
                                    {{ $f['id'] ?? '—' }}
                                    @if(! empty($f['cwe']))
                                        <span class="source-tag">{{ $f['cwe'] }}</span>
                                    @endif
                                </td>
                                <td>
                                    <div style="font-weight:600;color:var(--c-ink)">{{ $f['title'] ?? 'Untitled Finding' }}</div>
                                    <div class="surface-name" style="font-weight:500;color:var(--c-muted);margin-top:2px">{{ $f['endpoint'] ?? ($scan->target ?? '—') }}</div>
                                </td>
                                <td class="agent-cell">
                                    {{ $f['cvss_score'] ?? '—' }}
                                    <span class="source-tag">{{ $f['validation_status'] ?? 'confirmed' }}</span>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            @else
                <div class="posture-banner posture-safe" style="margin-bottom:0">
                    <div>
                        <h3>{{ $isEn ? 'Zero Confirmed Vulnerabilities' : 'Nol Kerentanan Terkonfirmasi' }}</h3>
                        <p>{{ $isEn ? 'No exploitable security findings were filed for this scan run.' : 'Tidak ada temuan kerentanan yang dapat dieksploitasi pada hasil pemindaian ini.' }}</p>
                    </div>
                </div>
            @endif
        </section>

        {{-- Section 4: Agent Execution & Coverage Gaps --}}
        <section class="report-section">
            <div class="section-heading">
                <h2>{{ $isEn ? '4. Assessment Agents, Modules & Coverage Gaps' : '4. Audit Agen, Modul Pengujian & Kesenjangan Cakupan' }}</h2>
                <span class="section-code">SEC-04 // AUDIT</span>
            </div>

            @if(! empty($skillsExercised))
                <div style="margin-bottom:16px">
                    <div style="font-size:11.5px;font-weight:600;color:var(--c-muted);margin-bottom:8px;">
                        {{ $isEn ? 'Security Assessment Modules Exercised:' : 'Modul Pengujian Keamanan yang Dijalankan:' }}
                    </div>
                    <div class="skill-list">
                        @foreach($skillsExercised as $skill)
                            <span class="skill-chip">{{ $skill }}</span>
                        @endforeach
                    </div>
                </div>
            @endif

            <div class="two-col-grid">
                <div>
                    <h3 style="font-size:13px;font-weight:600;margin-bottom:10px;color:var(--c-ink)">{{ $isEn ? 'Executed Assessment Agents' : 'Agen Pelaksana Pengujian' }}</h3>
                    @if(! empty($agents))
                        <table class="va-table">
                            <thead>
                                <tr>
                                    <th>{{ $isEn ? 'Agent' : 'Agen' }}</th>
                                    <th>{{ $isEn ? 'Status' : 'Status' }}</th>
                                    <th>{{ $isEn ? 'Modules' : 'Modul' }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                @foreach($agents as $agent)
                                    @php
                                        $agentSkills = is_array($agent['skills'] ?? null) ? implode(', ', $agent['skills']) : '—';
                                    @endphp
                                    <tr>
                                        <td>
                                            <div style="font-weight:600">{{ $agent['agent_name'] ?? ($agent['name'] ?? 'Agent') }}</div>
                                            <div class="source-tag">{{ ! empty($agent['is_root']) ? 'Coordinator' : 'Specialist' }}</div>
                                        </td>
                                        <td class="agent-cell">{{ strtoupper((string) ($agent['status'] ?? 'done')) }}</td>
                                        <td class="evidence-text">{{ $agentSkills !== '' ? $agentSkills : '—' }}</td>
                                    </tr>
                                @endforeach
                            </tbody>
                        </table>
                    @else
                        <div class="notice-box">{{ $isEn ? 'No agent telemetry recorded.' : 'Tidak ada telemetri agen tercatat.' }}</div>
                    @endif
                </div>

                <div>
                    <h3 style="font-size:13px;font-weight:600;margin-bottom:10px;color:var(--c-ink)">{{ $isEn ? 'Coverage Gaps & Unchecked Items' : 'Kesenjangan Cakupan (Gaps)' }}</h3>
                    @if(! empty($gaps))
                        <table class="va-table">
                            <thead>
                                <tr>
                                    <th style="width:110px">{{ $isEn ? 'Type' : 'Jenis' }}</th>
                                    <th>{{ $isEn ? 'Detail' : 'Keterangan' }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                @foreach($gaps as $gap)
                                    <tr class="row-followup">
                                        <td class="agent-cell">{{ $gap['kind'] ?? 'gap' }}</td>
                                        <td class="evidence-text">
                                            @if(! empty($gap['surface']))
                                                <strong>{{ $gap['surface'] }}</strong>
                                                @if(! empty($gap['risk_area']))
                                                    ({{ $gap['risk_area'] }})
                                                @endif
                                                —
                                            @endif
                                            {{ $gap['detail'] ?? ($isEn ? 'Requires manual verification.' : 'Memerlukan verifikasi lanjutan.') }}
                                        </td>
                                    </tr>
                                @endforeach
                            </tbody>
                        </table>
                    @else
                        <div class="notice-box" style="border-left-color:#059669;background:#f0fdf4;border-color:#bbf7d0;color:#065f46">
                            <strong>{{ $isEn ? 'No Coverage Gaps Flagged' : 'Tidak Ada Gap Tercatat' }}</strong> —
                            {{ $isEn ? 'All recorded checks reached a terminal assessment state.' : 'Seluruh pemeriksaan tercatat mencapai status evaluasi akhir.' }}
                        </div>
                    @endif
                </div>
            </div>
        </section>

        {{-- Section 5: Boundaries & Disclaimer --}}
        <section class="report-section">
            <div class="disclaimer-card">
                <p>
                    <strong>{{ $isEn ? 'Assessment Boundaries & Interpretation:' : 'Batasan Asesmen & Cara Membaca Laporan:' }}</strong>
                    {{ $isEn
                        ? 'This Vulnerability Assessment Report documents the exact surfaces, endpoints, and security checks actively exercised during this point-in-time black-box engagement. Items marked SAFE (No Issue Found / Ruled Out) reflect negative verification results under the tested conditions and credentials available at scan time, not an absolute guarantee against untested code paths or future application changes. This document complements — and does not replace — the detailed Penetration Test Report.'
                        : 'Laporan Vulnerability Assessment ini mendokumentasikan secara transparan seluruh permukaan, endpoint, dan skenario keamanan yang aktif diuji selama asesmen black-box pada waktu tersebut. Status AMAN (Bersih / Dieliminasi) menunjukkan bahwa pada kondisi, payload, dan cakupan saat pemindaian tidak ditemukan kerentanan yang dapat dieksploitasi, namun tidak menjamin komponen di luar ruang lingkup atau perubahan aplikasi setelah pemindaian. Dokumen ini melengkapi — bukan menggantikan — Laporan Pentest PDF.' }}
                </p>
            </div>
        </section>
    </div>

    <script>
        (function () {
            const pills = document.querySelectorAll('#va-filter-pills .filter-pill');
            const searchInput = document.getElementById('va-matrix-search');
            const rows = document.querySelectorAll('#va-matrix-table tbody tr');
            if (!rows.length) return;

            let activeGroup = 'all';
            const applyFilter = () => {
                const q = (searchInput ? searchInput.value : '').trim().toLowerCase();
                rows.forEach((row) => {
                    const groupMatch = activeGroup === 'all' || row.dataset.group === activeGroup;
                    const textMatch = !q || (row.dataset.search || '').includes(q);
                    row.style.display = groupMatch && textMatch ? '' : 'none';
                });
            };

            pills.forEach((btn) => {
                btn.addEventListener('click', () => {
                    pills.forEach((p) => p.classList.remove('active'));
                    btn.classList.add('active');
                    activeGroup = btn.dataset.filter || 'all';
                    applyFilter();
                });
            });

            if (searchInput) {
                searchInput.addEventListener('input', applyFilter);
            }
        })();
    </script>
</body>
</html>
