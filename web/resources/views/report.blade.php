@php
    $isEn = ($lang ?? 'id') === 'en';
    $target = $scan->target ?: 'https://target.local';
    $parsedHost = parse_url(str_contains($target, '://') ? $target : 'https://'.$target, PHP_URL_HOST) ?: $target;
    $dateStr = $scan->created_at ? $scan->created_at->format('d F Y') : now()->format('d F Y');
    $timeStr = $scan->created_at ? $scan->created_at->format('H:i T') : now()->format('H:i T');

    $counts = [
        'critical' => 0,
        'high' => 0,
        'medium' => 0,
        'low' => 0,
        'info' => 0,
    ];
    $maxCvss = 0.0;
    foreach ($findings as $f) {
        $sev = strtolower($f['severity'] ?? 'info');
        if (isset($counts[$sev])) {
            $counts[$sev]++;
        }
        $score = (float) ($f['cvss'] ?? 0.0);
        if ($score > $maxCvss) {
            $maxCvss = $score;
        }
    }
    $totalFindings = count($findings);

    // Strategic risk posture classification
    if ($counts['critical'] > 0 || $maxCvss >= 9.0) {
        $postureLevel = 'CRITICAL';
        $postureColor = '#dc2626';
        $postureTitle = $isEn ? 'Critical Risk Posture' : 'Tingkat Risiko Kritis';
        $postureDesc = $isEn
            ? 'The target demonstrates immediate, exploitable security vulnerabilities that expose administrative systems or sensitive operational data. Remediation is urgently required.'
            : 'Sistem target memiliki kerentanan keamanan berisiko kritis yang dapat dieksploitasi langsung untuk mengambil alih hak akses administratif atau mengekspos data operasional sensitif. Diperlukan tindakan remediasi darurat.';
    } elseif ($counts['high'] > 0 || $maxCvss >= 7.0) {
        $postureLevel = 'HIGH';
        $postureColor = '#ea580c';
        $postureTitle = $isEn ? 'High Risk Posture' : 'Tingkat Risiko Tinggi';
        $postureDesc = $isEn
            ? 'Severe vulnerabilities were identified that could allow significant unauthorized access, data compromise, or integrity violations.'
            : 'Ditemukan kerentanan tingkat tinggi yang berpotensi menyebabkan kebocoran data penting, bypass kontrol akses, atau manipulasi data sistem.';
    } elseif ($counts['medium'] > 0 || $maxCvss >= 4.0) {
        $postureLevel = 'MEDIUM';
        $postureColor = '#d97706';
        $postureTitle = $isEn ? 'Moderate Risk Posture' : 'Tingkat Risiko Sedang';
        $postureDesc = $isEn
            ? 'Several moderate vulnerabilities and configuration issues were identified that warrant scheduled remediation to prevent chain attacks.'
            : 'Ditemukan kerentanan dan kelemahan konfigurasi tingkat sedang yang memerlukan perbaikan terjadwal guna mencegah potensi eskalasi serangan rantai (attack chain).';
    } elseif ($totalFindings > 0) {
        $postureLevel = 'LOW';
        $postureColor = '#2563eb';
        $postureTitle = $isEn ? 'Low Risk Posture' : 'Tingkat Risiko Rendah';
        $postureDesc = $isEn
            ? 'Only low-severity or informational observations were discovered. Core security controls remain largely effective.'
            : 'Hanya ditemukan observasi kerentanan tingkat rendah atau informasional. Kontrol keamanan inti sistem secara umum berfungsi dengan baik.';
    } else {
        $postureLevel = 'SECURE';
        $postureColor = '#16a34a';
        $postureTitle = $isEn ? 'No Vulnerabilities Identified' : 'Tidak Ditemukan Kerentanan';
        $postureDesc = $isEn
            ? 'No exploitable vulnerabilities were identified within the tested attack surface during this assessment cycle.'
            : 'Tidak ditemukan kerentanan yang dapat dieksploitasi pada ruang lingkup target pengujian selama siklus audit ini.';
    }

    $severityNames = [
        'critical' => $isEn ? 'Critical' : 'Kritis',
        'high' => $isEn ? 'High' : 'Tinggi',
        'medium' => $isEn ? 'Medium' : 'Sedang',
        'low' => $isEn ? 'Low' : 'Rendah',
        'info' => $isEn ? 'Informational' : 'Informasional',
    ];

    $modeLabel = match(strtolower($scan->mode ?? 'standard')) {
        'quick' => $isEn ? 'Quick Scan' : 'Pemindaian Cepat',
        'deep' => $isEn ? 'Deep Scan' : 'Pemindaian Mendalam',
        default => $isEn ? 'Standard Black-box' : 'Pemindaian Standar (Black-box)',
    };

    // Determine vulnerability archetype for fallback templates and standard definitions
    $getArchetype = function (array $f): string {
        $cwe = strtolower((string) ($f['cwe'] ?? ''));
        $title = strtolower((string) ($f['title'] ?? ''));
        $desc = strtolower((string) ($f['description'] ?? ''));
        $haystack = "{$cwe} {$title} {$desc}";

        if (str_contains($haystack, 'sql') || str_contains($haystack, 'cwe-89')) return 'sqli';
        if (str_contains($haystack, 'xss') || str_contains($haystack, 'cross-site script') || str_contains($haystack, 'cwe-79')) return 'xss';
        if (str_contains($haystack, 'idor') || str_contains($haystack, 'direct object') || str_contains($haystack, 'cwe-639') || str_contains($haystack, 'cwe-284')) return 'idor';
        if (str_contains($haystack, 'rce') || str_contains($haystack, 'command injection') || str_contains($haystack, 'code execution') || str_contains($haystack, 'cwe-78') || str_contains($haystack, 'cwe-94')) return 'rce';
        if (str_contains($haystack, 'ssrf') || str_contains($haystack, 'server-side request') || str_contains($haystack, 'cwe-918')) return 'ssrf';
        if (str_contains($haystack, 'csrf') || str_contains($haystack, 'cross-site request') || str_contains($haystack, 'cwe-352')) return 'csrf';
        if (str_contains($haystack, 'traversal') || str_contains($haystack, 'lfi') || str_contains($haystack, 'cwe-22')) return 'traversal';
        if (str_contains($haystack, 'open redirect') || str_contains($haystack, 'cwe-601')) return 'redirect';
        if (str_contains($haystack, 'cors') || str_contains($haystack, 'misconfiguration')) return 'misconfig';
        if (str_contains($haystack, 'disclosure') || str_contains($haystack, 'leak') || str_contains($haystack, 'cwe-200')) return 'disclosure';

        return 'generic';
    };

    // Industry-standard bilingual Impact & Remediation dictionary (PTES / HackerOne VRT / BSSN)
    $archetypeTemplates = [
        'sqli' => [
            'impact_en' => 'Allows unauthenticated or unauthorized actors to extract, alter, or destroy database contents, potentially leading to administrative account compromise or arbitrary data exfiltration.',
            'impact_id' => 'Memungkinkan pihak tidak berwenang mengekstrak, mengubah, atau menghapus data dalam basis data, yang berpotensi memicu pengambilalihan akun administratif serta kebocoran data sensitif.',
            'remediation_en' => 'Employ parameterized queries (prepared statements) for all database operations. Enforce the principle of least privilege on database accounts.',
            'remediation_id' => 'Gunakan kueri berparameter (prepared statements) atau ORM pada seluruh operasi basis data. Terapkan prinsip hak akses minimal (least privilege) pada akun database.',
        ],
        'xss' => [
            'impact_en' => 'Permits execution of malicious JavaScript within the session context of victim users, enabling session hijacking, credential harvesting, DOM defacement, or CSRF token theft.',
            'impact_id' => 'Memungkinkan eksekusi skrip JavaScript berbahaya dalam konteks sesi peramban pengguna lain, membuka potensi pembajakan sesi, pencurian kredensial, manipulasi tampilan (defacement), atau pencurian token CSRF.',
            'remediation_en' => 'Contextually encode all user-controlled data before rendering into HTML, JavaScript, or attributes. Enforce a robust Content Security Policy (CSP).',
            'remediation_id' => 'Terapkan context-aware output encoding pada seluruh data pengguna sebelum dirender ke HTML atau JavaScript. Pasang header Content Security Policy (CSP) yang ketat.',
        ],
        'idor' => [
            'impact_en' => 'Enables attackers to bypass horizontal or vertical access controls, accessing or modifying other users\' confidential records simply by manipulating resource identifiers.',
            'impact_id' => 'Memungkinkan penyerang melewati kontrol otorisasi (akses horizontal maupun vertikal) untuk melihat atau mengubah data sensitif milik pengguna lain dengan memanipulasi parameter ID sumber daya.',
            'remediation_en' => 'Implement strict server-side authorization checks verifying that the authenticated user explicitly owns or has permissions for the requested object before serving data.',
            'remediation_id' => 'Terapkan validasi otorisasi di sisi server (server-side) yang memverifikasi bahwa pengguna yang terautentikasi memiliki hak akses eksplisit terhadap objek yang diminta.',
        ],
        'rce' => [
            'impact_en' => 'Provides arbitrary command execution on the underlying operating system, resulting in total server compromise, internal network pivot, and host data exfiltration.',
            'impact_id' => 'Menyediakan akses eksekusi perintah sistem operasi secara arbitrer, berakibat pada pengambilalihan kendali server secara menyeluruh, pivoting ke jaringan internal, dan eksfiltrasi data host.',
            'remediation_en' => 'Completely avoid executing system commands with user-supplied input. If unavoidable, use hardened execution APIs with argument whitelisting within an isolated sandbox.',
            'remediation_id' => 'Hindari pemanggilan fungsi eksekusi sistem dengan data masukan pengguna. Jika tidak dapat dihindari, gunakan API berparameter dengan whitelist ketat dalam lingkungan sandbox terisolasi.',
        ],
        'ssrf' => [
            'impact_en' => 'Allows attackers to coerce the application into dispatching forged requests to internal network services, cloud instance metadata APIs (169.254.169.254), or loopback services.',
            'impact_id' => 'Memungkinkan penyerang memaksa server mengirim permintaan ke layanan internal, endpoint metadata instance cloud (169.254.169.254), atau port loopback yang tidak terekspos ke internet.',
            'remediation_en' => 'Validate and sanitize destination URLs against a strict domain/IP allowlist. Disallow connections to loopback (127.0.0.1) and private IP ranges (RFC 1918 / link-local).',
            'remediation_id' => 'Lakukan validasi URL tujuan terhadap daftar izin (whitelist) domain dan port. Blokir seluruh koneksi ke alamat IP privat (RFC 1918), loopback, dan subnet metadata cloud.',
        ],
        'csrf' => [
            'impact_en' => 'Allows malicious external websites to trick authenticated victims into submitting unwanted state-changing requests, such as changing passwords or initiating funds transfers.',
            'impact_id' => 'Memungkinkan situs web eksternal berbahaya memperdaya korban yang terotentikasi untuk mengirimkan permintaan perubahan status tanpa disadari (seperti pergantian kata sandi atau email).',
            'remediation_en' => 'Implement unpredictable, cryptographically strong anti-CSRF tokens for all state-changing endpoints. Configure SameSite=Lax or SameSite=Strict on session cookies.',
            'remediation_id' => 'Terapkan token anti-CSRF yang kuat secara kriptografis pada setiap endpoint operasi mutasi data. Konfigurasikan atribut SameSite=Lax atau SameSite=Strict pada cookie sesi.',
        ],
        'traversal' => [
            'impact_en' => 'Allows reading or executing arbitrary files outside the intended web document root, exposing source code, password files (/etc/passwd), and server environment variables.',
            'impact_id' => 'Memungkinkan pembacaan atau eksekusi berkas di luar direktori web root yang ditentukan, mengekspos kode sumber aplikasi, konfigurasi basis data, dan berkas sistem operasi.',
            'remediation_en' => 'Sanitize file path parameters by rejecting dot-dot-slash (../) sequences. Resolve absolute canonical paths and verify they reside strictly within the intended directory base.',
            'remediation_id' => 'Lakukan sanitasi parameter berkas dengan menolak sekuens traversal (../). Gunakan fungsi validasi canonical path dan pastikan berkas berada dalam batas direktori yang diizinkan.',
        ],
        'disclosure' => [
            'impact_en' => 'Discloses sensitive architectural details, internal IP addresses, framework trace logs, or private API keys that aid adversaries in crafting targeted exploits.',
            'impact_id' => 'Membocorkan detail arsitektur internal, jejak debug (stack trace), alamat IP privat, atau kunci API yang mempermudah penyerang merancang serangan terarah lanjutan.',
            'remediation_en' => 'Disable verbose error logging and debug mode in production. Ensure sensitive headers, stack traces, and environment variables are stripped from public responses.',
            'remediation_id' => 'Nonaktifkan mode debug dan pesan kesalahan detail di lingkungan produksi. Pastikan respons publik tidak memuat metadata internal, konfigurasi sistem, atau jejak error.',
        ],
        'generic' => [
            'impact_en' => 'Could allow unauthorized actors to degrade service availability, manipulate application state, or gain access to restricted functionality.',
            'impact_id' => 'Dapat dimanfaatkan oleh pihak tidak berwenang untuk merusak ketersediaan layanan, memanipulasi integritas data aplikasi, atau mengakses fungsionalitas terbatas.',
            'remediation_en' => 'Review the affected endpoint logic, apply robust input validation, and verify that strict authorization gates are enforced before performing actions.',
            'remediation_id' => 'Tinjau logika endpoint yang terdampak, terapkan validasi masukan ketat, dan pastikan pemeriksaan otorisasi dijalankan sebelum eksekusi aksi.',
        ],
    ];

    // Contextual text translator & phrase normalizer (keeps code/payloads untouched while translating prose)
    $translateContent = function (?string $text, bool $isEn, string $fallbackType, string $archetype) use ($archetypeTemplates): string {
        $clean = trim((string) $text);
        if ($clean === '') {
            $tpl = $archetypeTemplates[$archetype] ?? $archetypeTemplates['generic'];
            $key = $fallbackType . '_' . ($isEn ? 'en' : 'id');
            return $tpl[$key] ?? '';
        }

        if ($isEn) {
            return $clean;
        }

        // Translation dictionary for Indonesian security reporting standards (BSSN / ISO 27001 style)
        $replacements = [
            'The application fails to ' => 'Aplikasi tidak ',
            'the application fails to ' => 'aplikasi tidak ',
            'An attacker can ' => 'Penyerang dapat ',
            'an attacker can ' => 'penyerang dapat ',
            'An attacker could ' => 'Penyerang berpotensi ',
            'an attacker could ' => 'penyerang berpotensi ',
            'Allows an attacker to ' => 'Memungkinkan penyerang untuk ',
            'allows an attacker to ' => 'memungkinkan penyerang untuk ',
            'This allows ' => 'Hal ini memungkinkan ',
            'this allows ' => 'hal ini memungkinkan ',
            'This vulnerability allows ' => 'Kerentanan ini memungkinkan ',
            'this vulnerability allows ' => 'kerentanan ini memungkinkan ',
            'arbitrary code execution' => 'eksekusi kode arbitrer (RCE)',
            'unauthorized access' => 'akses tidak sah (tanpa izin)',
            'sensitive data exposure' => 'kebocoran data sensitif',
            'sensitive data' => 'data sensitif',
            'sensitive information' => 'informasi sensitif',
            'database compromise' => 'pengambilalihan basis data',
            'input validation' => 'validasi input',
            'access control' => 'kontrol akses',
            'parameter tampering' => 'manipulasi parameter',
            'rate limiting' => 'pembatasan laju permintaan (rate limiting)',
            'privilege escalation' => 'eskalasi hak akses',
            'bypass authentication' => 'melewati mekanisme otentikasi',
            'bypass authorization' => 'melewati mekanisme otorisasi',
            'denial of service' => 'penolakan layanan (DoS)',
            'information disclosure' => 'pengungkapan informasi sensitif',
            'cross-site scripting' => 'Cross-Site Scripting (XSS)',
            'SQL injection' => 'SQL Injection',
            'prepared statements' => 'prepared statements (kueri berparameter)',
            'output encoding' => 'output encoding (penyandian keluaran)',
            'least privilege' => 'prinsip hak akses terendah (least privilege)',
            'production environment' => 'lingkungan produksi',
            'debug mode' => 'mode debug',
        ];

        return str_ireplace(array_keys($replacements), array_values($replacements), $clean);
    };
@endphp
<!DOCTYPE html>
<html lang="{{ $isEn ? 'en' : 'id' }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ $isEn ? 'Security Assessment Report' : 'Laporan Asesmen Keamanan' }} · {{ $parsedHost }}</title>
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
            --c-primary: #0f172a;
            --c-accent: #0284c7;
            --c-critical: #dc2626;
            --c-high: #ea580c;
            --c-medium: #d97706;
            --c-low: #2563eb;
            --c-info: #64748b;
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
            font-size: 13.5px;
            line-height: 1.65;
            -webkit-font-smoothing: antialiased;
        }

        /* Interactive Floating Action Bar (Hidden on print) */
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

        .btn-toolbar-print {
            background: #53d4c3;
            color: #071d1a;
            font-weight: 600;
        }
        .btn-toolbar-print:hover {
            background: #6fe0d1;
            box-shadow: 0 0 16px rgba(83, 212, 195, 0.4);
        }

        .btn-toolbar-ai {
            background: #172554;
            color: #93c5fd;
            border-color: #1e3a8a;
            font-weight: 600;
        }
        .btn-toolbar-ai:hover {
            background: #1e3a8a;
            color: #ffffff;
            border-color: #3b82f6;
            box-shadow: 0 0 16px rgba(59, 130, 246, 0.35);
        }
        .btn-toolbar-ai.is-loading {
            opacity: 0.75;
            cursor: wait;
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
            gap: 6px;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 500;
            color: #8da1b5;
            text-decoration: none;
            transition: all 0.15s ease;
        }
        .lang-switch a.active {
            background: #1e2d3d;
            color: #ffffff;
            font-weight: 600;
        }
        .lang-switch a:hover:not(.active) {
            color: #ffffff;
        }

        /* Document Wrapper */
        .report-page-wrapper {
            max-width: 900px;
            margin: 32px auto 64px;
            background: var(--c-surface);
            box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            overflow: hidden;
        }

        .report-content {
            padding: 64px 72px;
        }

        /* Cover Page */
        .cover-page {
            border-bottom: 2px solid var(--c-ink);
            padding-bottom: 56px;
            margin-bottom: 56px;
        }

        .cover-badge-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 40px;
        }

        .confidential-stamp {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            padding: 4px 12px;
            border-radius: 4px;
            background: #fef2f2;
            color: #b91c1c;
            border: 1.5px solid #f87171;
        }

        .report-engine-tag {
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--c-subtle);
            letter-spacing: 0.05em;
        }

        .cover-title {
            font-size: 32px;
            line-height: 1.25;
            font-weight: 700;
            letter-spacing: -0.03em;
            color: var(--c-ink);
            margin-bottom: 12px;
        }

        .cover-subtitle {
            font-size: 15px;
            color: var(--c-muted);
            font-weight: 400;
            line-height: 1.6;
            margin-bottom: 44px;
            text-align: justify;
            text-justify: inter-word;
        }

        .meta-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 18px 24px;
            background: #f8fafc;
            border: 1px solid var(--c-border);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 32px;
        }

        .meta-item {
            display: flex;
            flex-direction: column;
            gap: 3px;
        }

        .meta-label {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--c-subtle);
        }

        .meta-value {
            font-size: 14px;
            font-weight: 600;
            color: var(--c-ink);
            word-break: break-all;
        }

        .meta-value.mono {
            font-family: var(--font-mono);
            font-size: 13px;
        }

        /* Executive Summary Section */
        .report-section {
            margin-bottom: 48px;
        }

        .section-header-box {
            display: flex;
            align-items: baseline;
            gap: 12px;
            border-bottom: 2px solid var(--c-ink);
            padding-bottom: 10px;
            margin-bottom: 24px;
        }

        .section-num {
            font-family: var(--font-mono);
            font-size: 16px;
            font-weight: 700;
            color: var(--c-accent);
        }

        .section-title {
            font-size: 20px;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: var(--c-ink);
        }

        .posture-banner {
            display: flex;
            align-items: flex-start;
            gap: 20px;
            background: #ffffff;
            border: 1px solid var(--c-border);
            border-left: 6px solid {{ $postureColor }};
            border-radius: 8px;
            padding: 20px 24px;
            margin-bottom: 28px;
            box-shadow: 0 4px 12px -2px rgba(0, 0, 0, 0.04);
        }

        .posture-score-box {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-width: 90px;
            padding: 10px;
            background: #f8fafc;
            border-radius: 6px;
            border: 1px solid var(--c-border);
            text-align: center;
        }

        .posture-score-num {
            font-size: 26px;
            font-weight: 800;
            color: {{ $postureColor }};
            font-family: var(--font-mono);
            line-height: 1;
        }

        .posture-score-label {
            font-size: 9.5px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--c-subtle);
            margin-top: 4px;
        }

        .posture-info h4 {
            font-size: 15px;
            font-weight: 600;
            color: var(--c-ink);
            margin-bottom: 4px;
        }

        .posture-info p {
            font-size: 13px;
            color: var(--c-muted);
            line-height: 1.65;
            text-align: justify;
            text-justify: inter-word;
        }

        /* Severity Cards Row */
        .severity-cards-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            margin-bottom: 28px;
        }

        .sev-card {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 14px 10px;
            background: #f8fafc;
            border: 1px solid var(--c-border);
            border-radius: 8px;
            text-align: center;
        }

        .sev-card-count {
            font-size: 22px;
            font-weight: 700;
            font-family: var(--font-mono);
            line-height: 1;
            margin-bottom: 4px;
        }
        .sev-card.critical .sev-card-count { color: var(--c-critical); }
        .sev-card.high .sev-card-count { color: var(--c-high); }
        .sev-card.medium .sev-card-count { color: var(--c-medium); }
        .sev-card.low .sev-card-count { color: var(--c-low); }
        .sev-card.info .sev-card-count { color: var(--c-info); }

        .sev-card-label {
            font-size: 11px;
            font-weight: 600;
            color: var(--c-subtle);
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        /* Scope & Methodology */
        .text-lead {
            font-size: 13.5px;
            color: var(--c-ink);
            line-height: 1.75;
            margin-bottom: 16px;
            text-align: justify;
            text-justify: inter-word;
        }

        .methodology-list {
            margin: 16px 0 24px 20px;
            color: var(--c-muted);
            font-size: 13px;
            line-height: 1.75;
            text-align: justify;
            text-justify: inter-word;
        }
        .methodology-list li {
            margin-bottom: 6px;
        }
        .methodology-list strong {
            color: var(--c-ink);
        }

        /* Summary Table */
        .report-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12.5px;
            margin-bottom: 32px;
            border: 1px solid var(--c-border);
            border-radius: 8px;
            overflow: hidden;
        }

        .report-table th {
            background: #f1f5f9;
            color: var(--c-ink);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 10.5px;
            letter-spacing: 0.05em;
            padding: 10px 14px;
            border-bottom: 1px solid var(--c-border);
            text-align: left;
        }

        .report-table td {
            padding: 12px 14px;
            border-bottom: 1px solid var(--c-border);
            color: var(--c-muted);
            vertical-align: middle;
        }
        .report-table tr:last-child td {
            border-bottom: 0;
        }

        .sev-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 2.5px 8px;
            border-radius: 4px;
            font-size: 10.5px;
            font-weight: 700;
            font-family: var(--font-mono);
            letter-spacing: 0.04em;
            text-transform: uppercase;
            white-space: nowrap;
        }
        .sev-badge.critical { background: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; }
        .sev-badge.high { background: #ffedd5; color: #c2410c; border: 1px solid #fdba74; }
        .sev-badge.medium { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
        .sev-badge.low { background: #dbeafe; color: #1d4ed8; border: 1px solid #93c5fd; }
        .sev-badge.info { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }

        .cvss-score-pill {
            font-family: var(--font-mono);
            font-weight: 700;
            font-size: 11px;
            color: var(--c-ink);
        }

        /* Detailed Vulnerabilities */
        .finding-detail-card {
            border: 1px solid var(--c-border);
            border-radius: 10px;
            background: #ffffff;
            margin-bottom: 32px;
            overflow: hidden;
            box-shadow: 0 4px 14px -3px rgba(0, 0, 0, 0.05);
            page-break-inside: avoid;
            break-inside: avoid;
        }

        .finding-detail-header {
            background: #f8fafc;
            border-bottom: 1px solid var(--c-border);
            padding: 18px 24px;
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 16px;
        }

        .finding-title-group h3 {
            font-size: 16.5px;
            font-weight: 700;
            color: var(--c-ink);
            letter-spacing: -0.015em;
            margin-bottom: 4px;
        }

        .finding-ref-id {
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--c-subtle);
            font-weight: 500;
        }

        .finding-pills {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-shrink: 0;
        }

        .finding-body {
            padding: 24px;
        }

        .finding-meta-table {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px 18px;
            background: #f8fafc;
            border: 1px solid var(--c-border);
            border-radius: 6px;
            padding: 14px 18px;
            margin-bottom: 22px;
        }

        .fmt-row {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        .fmt-key {
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--c-subtle);
        }
        .fmt-val {
            font-size: 12.5px;
            font-weight: 600;
            color: var(--c-ink);
            word-break: break-all;
        }
        .fmt-val.code {
            font-family: var(--font-mono);
            font-size: 11.5px;
            color: #0369a1;
        }

        .field-subheading {
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--c-ink);
            margin: 20px 0 8px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .field-subheading::before {
            content: "";
            width: 3px;
            height: 12px;
            background: var(--c-accent);
            border-radius: 2px;
        }

        .field-narrative {
            font-size: 13px;
            line-height: 1.75;
            color: var(--c-muted);
            margin-bottom: 14px;
            white-space: pre-wrap;
            text-align: justify;
            text-justify: inter-word;
        }

        .code-block {
            background: #090e17;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 14px 16px;
            color: #e2e8f0;
            font-family: var(--font-mono);
            font-size: 11.5px;
            line-height: 1.6;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            margin: 8px 0 16px;
            text-align: left;
        }

        .remediation-box {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 8px;
            padding: 14px 18px;
            margin-top: 18px;
        }
        .remediation-box h5 {
            font-size: 12px;
            font-weight: 700;
            color: #15803d;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            margin-bottom: 6px;
        }
        .remediation-box p {
            font-size: 12.5px;
            line-height: 1.7;
            color: #166534;
            white-space: pre-wrap;
            text-align: justify;
            text-justify: inter-word;
        }

        /* Disclaimer & Sign-off */
        .disclaimer-card {
            background: #f8fafc;
            border: 1px solid var(--c-border);
            border-radius: 8px;
            padding: 20px 24px;
            font-size: 12px;
            line-height: 1.65;
            color: var(--c-subtle);
            margin-top: 48px;
        }

        .disclaimer-card p {
            text-align: justify;
            text-justify: inter-word;
        }

        .disclaimer-card strong {
            color: var(--c-ink);
        }

        /* AI Loading Modal (Modern Glassmorphism Popup) */
        .ai-loading-modal {
            border: none;
            background: transparent;
            padding: 0;
            max-width: 480px;
            width: 90%;
            margin: auto;
            outline: none;
        }
        .ai-loading-modal::backdrop {
            background: rgba(6, 11, 18, 0.85);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
        }
        .ai-modal-box {
            background: #0d1520;
            border: 1px solid rgba(83, 212, 195, 0.28);
            border-radius: 18px;
            padding: 36px 30px 28px;
            color: #e2e8f0;
            text-align: center;
            box-shadow: 0 25px 70px -15px rgba(0, 0, 0, 0.85), 0 0 50px rgba(83, 212, 195, 0.12);
            position: relative;
            overflow: hidden;
        }
        .ai-modal-box::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #0284c7, #53d4c3, #38bdf8, #0284c7);
            background-size: 200% 100%;
            animation: gradientMove 3s linear infinite;
        }
        @keyframes gradientMove {
            0% { background-position: 100% 0; }
            100% { background-position: -100% 0; }
        }

        /* Glowing Cyber Orb Animation */
        .ai-cyber-orb {
            position: relative;
            width: 76px;
            height: 76px;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .orb-pulse-ring {
            position: absolute;
            inset: 0;
            border-radius: 50%;
            border: 1.5px solid rgba(83, 212, 195, 0.45);
            animation: orbPulse 2.4s cubic-bezier(0.215, 0.61, 0.355, 1) infinite;
        }
        .orb-pulse-ring.ring-2 {
            animation-delay: 1.2s;
        }
        @keyframes orbPulse {
            0% { transform: scale(0.65); opacity: 0.9; }
            100% { transform: scale(1.65); opacity: 0; }
        }
        .orb-core {
            position: relative;
            width: 54px;
            height: 54px;
            border-radius: 50%;
            background: radial-gradient(circle, #162c45 0%, #0b1420 100%);
            border: 1.5px solid #53d4c3;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #53d4c3;
            box-shadow: 0 0 28px rgba(83, 212, 195, 0.45);
            animation: orbRotate 6s ease-in-out infinite alternate;
        }
        @keyframes orbRotate {
            0% { transform: rotate(-8deg); }
            100% { transform: rotate(8deg); }
        }

        .ai-modal-title {
            font-size: 18.5px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: -0.015em;
            margin-bottom: 6px;
        }
        .ai-modal-subtitle {
            font-size: 12.5px;
            color: #94a3b8;
            line-height: 1.6;
            margin-bottom: 22px;
            text-align: center;
        }

        /* Step List */
        .ai-steps-list {
            display: flex;
            flex-direction: column;
            gap: 11px;
            background: #070d14;
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 16px 18px;
            margin-bottom: 22px;
            text-align: left;
        }
        .ai-step-item {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 12px;
            color: #475569;
            transition: all 0.3s ease;
        }
        .ai-step-item.is-active {
            color: #f8fafc;
            font-weight: 600;
        }
        .ai-step-item.is-done {
            color: #53d4c3;
        }
        .step-indicator {
            width: 18px;
            height: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }
        .step-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #334155;
            transition: all 0.3s ease;
        }
        .ai-step-item.is-active .step-dot {
            background: #0284c7;
        }
        .step-spinner {
            width: 14px;
            height: 14px;
            border: 2px solid rgba(83, 212, 195, 0.2);
            border-top-color: #53d4c3;
            border-radius: 50%;
            animation: stepSpin 0.75s linear infinite;
        }
        @keyframes stepSpin {
            to { transform: rotate(360deg); }
        }
        .step-check-icon {
            width: 14px;
            height: 14px;
            stroke: #53d4c3;
        }

        /* Progress Bar */
        .ai-progress-track {
            width: 100%;
            height: 6px;
            background: #172433;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 14px;
        }
        .ai-progress-bar {
            width: 15%;
            height: 100%;
            background: linear-gradient(90deg, #0284c7, #53d4c3);
            border-radius: 4px;
            transition: width 0.5s ease;
            box-shadow: 0 0 12px rgba(83, 212, 195, 0.6);
        }

        .ai-modal-footer {
            display: flex;
            justify-content: center;
        }
        .ai-modal-tip {
            font-family: var(--font-mono);
            font-size: 11px;
            color: #64748b;
        }

        /* PRINT STYLESHEET (High-Quality PDF Rendering) */
        @media print {
            body {
                background: #ffffff !important;
                color: #0f172a !important;
                font-size: 11.5pt;
                line-height: 1.55;
            }

            .report-toolbar, .ai-loading-modal {
                display: none !important;
            }

            .report-page-wrapper {
                max-width: 100% !important;
                margin: 0 !important;
                box-shadow: none !important;
                border-radius: 0 !important;
                border: 0 !important;
            }

            .report-content {
                padding: 0 !important;
            }

            .cover-page {
                page-break-after: always;
                break-after: page;
                min-height: 90vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
                border-bottom: 0;
                margin-bottom: 0;
                padding-bottom: 0;
            }

            .report-section {
                page-break-inside: auto;
                break-inside: auto;
            }

            .finding-detail-card {
                page-break-inside: avoid;
                break-inside: avoid;
                margin-bottom: 24pt;
                border: 1pt solid #cbd5e1;
                box-shadow: none;
            }

            .code-block {
                background: #f8fafc !important;
                color: #0f172a !important;
                border: 1pt solid #cbd5e1 !important;
                page-break-inside: avoid;
                break-inside: avoid;
            }

            .confidential-stamp {
                border: 1.5pt solid #dc2626 !important;
                color: #dc2626 !important;
                background: #fee2e2 !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }

            .posture-banner, .meta-grid, .finding-detail-header, .finding-meta-table, .remediation-box {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }

            .sev-badge {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }

            @page {
                size: A4 portrait;
                margin: 18mm 14mm 18mm 14mm;
            }
        }
    </style>
</head>
<body>

    <!-- Interactive Navigation Bar -->
    <header class="report-toolbar">
        <div class="toolbar-left">
            <a href="{{ route('scans.show', $scan) }}" class="btn-toolbar btn-toolbar-back">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
                <span>{{ $isEn ? 'Back to Scan' : 'Kembali ke Pemindaian' }}</span>
            </a>
            <div class="lang-switch" role="group" aria-label="Pilihan Bahasa">
                <a href="{{ route('scans.report', [$scan, 'lang' => 'id']) }}" @class(['active' => !$isEn])>🇮🇩 ID</a>
                <a href="{{ route('scans.report', [$scan, 'lang' => 'en']) }}" @class(['active' => $isEn])>🇬🇧 EN</a>
            </div>
        </div>

        <div class="toolbar-right">
            <button id="btn-synthesize" type="button" class="btn-toolbar btn-toolbar-ai" title="{{ $isEn ? 'Synthesize professional report narratives in ID & EN with AI' : 'Parafrase narasi laporan profesional dalam ID & EN menggunakan AI' }}">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
                <span id="btn-synthesize-text">{{ $hasAiReport ? ($isEn ? '✨ AI Synthesized' : '✨ Laporan AI Aktif') : ($isEn ? '✨ Synthesize with AI' : '✨ Parafrase Laporan (AI)') }}</span>
            </button>
            <button onclick="window.print()" class="btn-toolbar btn-toolbar-print" title="{{ $isEn ? 'Print or Save as PDF' : 'Cetak atau Simpan sebagai PDF' }}">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
                <span>{{ $isEn ? 'Print / Export PDF' : 'Cetak / Simpan PDF' }}</span>
            </button>
        </div>
    </header>

    <!-- Main Printable Report Canvas -->
    <main class="report-page-wrapper">
        <article class="report-content">

            <!-- 1. COVER PAGE -->
            <section class="cover-page">
                <div class="cover-badge-row">
                    <span class="confidential-stamp">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                        {{ $isEn ? 'Strictly Confidential' : 'Dokumen Rahasia & Terbatas' }}
                    </span>
                    <span class="report-engine-tag">PENTESIN MULTI-AGENT SEC OPS · v1.0</span>
                </div>

                <h1 class="cover-title">
                    {{ $isEn ? 'Web Application Penetration Testing & Vulnerability Assessment Report' : 'Laporan Pengujian Penetrasi & Asesmen Kerentanan Aplikasi Web' }}
                </h1>
                <p class="cover-subtitle">
                    {{ $isEn
                        ? 'Comprehensive dynamic security assessment, attack surface analysis, and verification of vulnerabilities conducted in accordance with international security standards (OWASP / PTES / HackerOne).'
                        : 'Evaluasi keamanan dinamis (DAST), analisis bidang serang, dan verifikasi celah keamanan berbasis standar pengujian keamanan internasional (OWASP / PTES / HackerOne).'
                    }}
                </p>

                <div class="meta-grid">
                    <div class="meta-item">
                        <span class="meta-label">{{ $isEn ? 'Target System' : 'Sistem Target' }}</span>
                        <span class="meta-value mono">{{ $target }}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">{{ $isEn ? 'Assessment Date' : 'Tanggal Pengujian' }}</span>
                        <span class="meta-value">{{ $dateStr }} ({{ $timeStr }})</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">{{ $isEn ? 'Assessment Mode' : 'Mode Asesmen' }}</span>
                        <span class="meta-value">{{ $modeLabel }}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">{{ $isEn ? 'Testing Framework' : 'Metodologi Pengujian' }}</span>
                        <span class="meta-value">PTES &amp; OWASP Top 10 (2025)</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">{{ $isEn ? 'Security Assessor' : 'Pelaksana Audit' }}</span>
                        <span class="meta-value">Pentesin Autonomous Multi-Agent Engine</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">{{ $isEn ? 'Report Classification' : 'Klasifikasi Dokumen' }}</span>
                        <span class="meta-value">TLP:AMBER / Restricted</span>
                    </div>
                </div>
            </section>

            <!-- 2. EXECUTIVE SUMMARY -->
            <section class="report-section">
                <header class="section-header-box">
                    <span class="section-num">01</span>
                    <h2 class="section-title">{{ $isEn ? 'Executive Summary' : 'Ringkasan Eksekutif' }}</h2>
                </header>

                <p class="text-lead">
                    {{ $isEn
                        ? "During the assessment period, Pentesin's autonomous multi-agent testing engine conducted a targeted black-box penetration test against {$target}. The objective was to discover, validate, and verify potential security weaknesses that could be leveraged by adversaries to compromise confidentiality, integrity, or availability."
                        : "Selama periode audit, mesin multi-agent otonom Pentesin melaksanakan pengujian penetrasi terarah (black-box) terhadap {$target}. Tujuan pengujian adalah mengidentifikasi, menguji coba, dan memverifikasi kerentanan keamanan yang dapat dimanfaatkan oleh pihak tidak berwenang untuk merusak kerahasiaan, integritas, atau ketersediaan sistem."
                    }}
                </p>

                <!-- Overall Risk Posture Banner -->
                <div class="posture-banner">
                    <div class="posture-score-box">
                        <span class="posture-score-num">{{ number_format($maxCvss, 1) }}</span>
                        <span class="posture-score-label">Max CVSS</span>
                    </div>
                    <div class="posture-info">
                        <h4>{{ $postureTitle }}</h4>
                        <p>{{ $postureDesc }}</p>
                    </div>
                </div>

                <!-- Severity Metric Tiles -->
                <div class="severity-cards-grid">
                    <div class="sev-card critical">
                        <span class="sev-card-count">{{ $counts['critical'] }}</span>
                        <span class="sev-card-label">{{ $severityNames['critical'] }}</span>
                    </div>
                    <div class="sev-card high">
                        <span class="sev-card-count">{{ $counts['high'] }}</span>
                        <span class="sev-card-label">{{ $severityNames['high'] }}</span>
                    </div>
                    <div class="sev-card medium">
                        <span class="sev-card-count">{{ $counts['medium'] }}</span>
                        <span class="sev-card-label">{{ $severityNames['medium'] }}</span>
                    </div>
                    <div class="sev-card low">
                        <span class="sev-card-count">{{ $counts['low'] }}</span>
                        <span class="sev-card-label">{{ $severityNames['low'] }}</span>
                    </div>
                    <div class="sev-card info">
                        <span class="sev-card-count">{{ $counts['info'] }}</span>
                        <span class="sev-card-label">{{ $severityNames['info'] }}</span>
                    </div>
                </div>
            </section>

            <!-- 3. SCOPE & METHODOLOGY -->
            <section class="report-section">
                <header class="section-header-box">
                    <span class="section-num">02</span>
                    <h2 class="section-title">{{ $isEn ? 'Scope & Testing Methodology' : 'Ruang Lingkup & Metodologi Pengujian' }}</h2>
                </header>

                <p class="text-lead">
                    {{ $isEn
                        ? 'The security audit follows the Penetration Testing Execution Standard (PTES) and the OWASP Web Security Testing Guide (WSTG v4.2). The testing engine operates strictly within authorized scopes, employing coordinated specialized subagents for reconnaissance, surface mapping, parameter fuzzing, and vulnerability verification.'
                        : 'Audit keamanan ini mengacu pada standar internasional Penetration Testing Execution Standard (PTES) dan OWASP Web Security Testing Guide (WSTG v4.2). Mesin pengujian bekerja dalam koridor ruang lingkup yang diotorisasi, mengoordinasikan subagent spesialis untuk tahap pengintaian, pemetaan endpoint, fuzzing parameter, hingga verifikasi celah keamanan.'
                    }}
                </p>

                <ul class="methodology-list">
                    <li>
                        <strong>{{ $isEn ? 'Reconnaissance & Asset Mapping' : 'Pengintaian & Pemetaan Aset' }}:</strong>
                        {{ $isEn ? 'Automated endpoint discovery, virtual host mapping, technology stack fingerprinting, and directory enumeration.' : 'Penemuan endpoint otomatis, pemetaan subdomain/virtual host, identifikasi fingerprint teknologi web server, serta enumerasi direktori.' }}
                    </li>
                    <li>
                        <strong>{{ $isEn ? 'Vulnerability Analysis & Fuzzing' : 'Analisis Kerentanan & Fuzzing' }}:</strong>
                        {{ $isEn ? 'Systematic probing for OWASP Top 10 vulnerabilities including Authentication Bypass, IDOR, SQLi, XSS, SSRF, and sensitive data exposures.' : 'Pengujian sistematis terhadap risiko OWASP Top 10 meliputi kontrol akses, pembobolan otentikasi (IDOR), SQL Injection, XSS, kebocoran data sensitif, dan miskonfigurasi.' }}
                    </li>
                    <li>
                        <strong>{{ $isEn ? 'Active Verification & Proof of Concept' : 'Verifikasi Aktif & Proof of Concept (PoC)' }}:</strong>
                        {{ $isEn ? 'Safe, non-destructive execution of reproduction steps to eliminate false positives and validate real-world exploitability.' : 'Eksekusi pembuktian konsep (PoC) secara non-destruktif untuk mengeliminasi false positive dan memvalidasi potensi dampak nyata.' }}
                    </li>
                </ul>
            </section>

            <!-- 4. VULNERABILITY SUMMARY TABLE -->
            <section class="report-section">
                <header class="section-header-box">
                    <span class="section-num">03</span>
                    <h2 class="section-title">{{ $isEn ? 'Vulnerability Findings Summary' : 'Tabel Ringkasan Temuan Kerentanan' }}</h2>
                </header>

                @if(count($findings) > 0)
                    <table class="report-table">
                        <thead>
                            <tr>
                                <th style="width: 14%;">ID</th>
                                <th>{{ $isEn ? 'Vulnerability Title' : 'Judul Kerentanan' }}</th>
                                <th style="width: 18%;">{{ $isEn ? 'Severity' : 'Tingkat' }}</th>
                                <th style="width: 12%;">CVSS</th>
                                <th style="width: 16%;">CWE</th>
                            </tr>
                        </thead>
                        <tbody>
                            @foreach($findings as $f)
                                @php
                                    $fSev = strtolower($f['severity'] ?? 'info');
                                    $cweVal = $f['cwe'] ?? ($f['finding_class'] ?? '—');
                                    $arch = $getArchetype($f);
                                    $tableTitle = $translateContent($f['title'] ?? 'Unnamed Vulnerability', $isEn, 'title', $arch);
                                @endphp
                                <tr>
                                    <td class="mono" style="font-weight: 600; font-size: 11px;">{{ $f['id'] ?? 'vuln-'.sprintf('%04d', $loop->iteration) }}</td>
                                    <td>
                                        <strong style="color: var(--c-ink); font-size: 13px;">{{ $tableTitle }}</strong>
                                        <div style="font-size: 11px; color: var(--c-subtle); margin-top: 2px;">{{ $f['target'] ?? $f['endpoint'] ?? '' }}</div>
                                    </td>
                                    <td>
                                        <span class="sev-badge {{ $fSev }}">{{ $severityNames[$fSev] ?? $fSev }}</span>
                                    </td>
                                    <td class="cvss-score-pill">{{ isset($f['cvss']) ? number_format((float)$f['cvss'], 1) : '—' }}</td>
                                    <td class="mono" style="font-size: 11.5px;">{{ $cweVal }}</td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                @else
                    <p style="color: var(--c-subtle); font-style: italic; padding: 16px 0;">
                        {{ $isEn ? 'No vulnerabilities were identified during this assessment.' : 'Tidak ada kerentanan yang terdeteksi selama pengujian ini.' }}
                    </p>
                @endif
            </section>

            <!-- 5. DETAILED VULNERABILITY FINDINGS (HACKERONE / BUG BOUNTY STANDARD) -->
            <section class="report-section">
                <header class="section-header-box">
                    <span class="section-num">04</span>
                    <h2 class="section-title">{{ $isEn ? 'Detailed Vulnerability Findings' : 'Laporan Rinci Temuan Kerentanan' }}</h2>
                </header>

                @forelse($findings as $f)
                    @php
                        $fSev = strtolower($f['severity'] ?? 'info');
                        $vulnId = $f['id'] ?? 'vuln-'.sprintf('%04d', $loop->iteration);
                        $cvssVal = isset($f['cvss']) ? number_format((float)$f['cvss'], 1) : 'N/A';
                        $archetype = $getArchetype($f);

                        $title = $translateContent($f['title'] ?? 'Untitled Security Finding', $isEn, 'title', $archetype);
                        $description = $translateContent($f['description'] ?? ($isEn ? 'No detailed description provided.' : 'Deskripsi teknis tidak disediakan.'), $isEn, 'description', $archetype);
                        $impact = $translateContent($f['impact'] ?? '', $isEn, 'impact', $archetype);
                        $techAnalysis = $translateContent($f['technical_analysis'] ?? '', $isEn, 'technical_analysis', $archetype);
                        $pocDesc = $translateContent($f['poc_description'] ?? '', $isEn, 'poc_description', $archetype);
                        $remediation = $translateContent($f['remediation_steps'] ?? '', $isEn, 'remediation', $archetype);
                    @endphp
                    <article class="finding-detail-card" id="{{ $vulnId }}">
                        <!-- Card Header -->
                        <div class="finding-detail-header">
                            <div class="finding-title-group">
                                <span class="finding-ref-id">{{ $vulnId }}</span>
                                <h3>{{ $title }}</h3>
                            </div>
                            <div class="finding-pills">
                                <span class="sev-badge {{ $fSev }}">{{ $severityNames[$fSev] ?? $fSev }}</span>
                                <span class="cvss-score-pill">CVSS {{ $cvssVal }}</span>
                            </div>
                        </div>

                        <!-- Card Body -->
                        <div class="finding-body">
                            <!-- Technical Meta Table -->
                            <div class="finding-meta-table">
                                <div class="fmt-row">
                                    <span class="fmt-key">{{ $isEn ? 'Vulnerable Asset' : 'Aset Terdampak' }}</span>
                                    <span class="fmt-val code">{{ $f['target'] ?? $target }}</span>
                                </div>
                                @if(!empty($f['endpoint']))
                                    <div class="fmt-row">
                                        <span class="fmt-key">{{ $isEn ? 'Vulnerable Endpoint' : 'Endpoint / URL' }}</span>
                                        <span class="fmt-val code">{{ $f['endpoint'] }}</span>
                                    </div>
                                @endif
                                @if(!empty($f['method']))
                                    <div class="fmt-row">
                                        <span class="fmt-key">{{ $isEn ? 'HTTP Method' : 'Metode HTTP' }}</span>
                                        <span class="fmt-val">{{ strtoupper($f['method']) }}</span>
                                    </div>
                                @endif
                                <div class="fmt-row">
                                    <span class="fmt-key">CWE Identifier</span>
                                    <span class="fmt-val">{{ $f['cwe'] ?? 'CWE-Unknown' }}</span>
                                </div>
                                @if(!empty($f['agent_name']))
                                    <div class="fmt-row">
                                        <span class="fmt-key">{{ $isEn ? 'Reporting Agent' : 'Agent Pelapor' }}</span>
                                        <span class="fmt-val">{{ $f['agent_name'] }}</span>
                                    </div>
                                @endif
                            </div>

                            <!-- Description -->
                            <h4 class="field-subheading">{{ $isEn ? 'Vulnerability Description' : 'Deskripsi Kerentanan' }}</h4>
                            <div class="field-narrative">{{ $description }}</div>

                            <!-- Impact -->
                            @if(!empty($impact))
                                <h4 class="field-subheading">{{ $isEn ? 'Business & Technical Impact' : 'Analisis Dampak Risiko' }}</h4>
                                <div class="field-narrative">{{ $impact }}</div>
                            @endif

                            <!-- Technical Analysis -->
                            @if(!empty($techAnalysis))
                                <h4 class="field-subheading">{{ $isEn ? 'Technical Root Cause Analysis' : 'Analisis Teknis & Akar Masalah' }}</h4>
                                <div class="field-narrative">{{ $techAnalysis }}</div>
                            @endif

                            <!-- Steps to Reproduce -->
                            @if(!empty($pocDesc))
                                <h4 class="field-subheading">{{ $isEn ? 'Steps to Reproduce' : 'Langkah-Langkah Reproduksi' }}</h4>
                                <div class="field-narrative">{{ $pocDesc }}</div>
                            @endif

                            <!-- Proof of Concept Code / Request -->
                            @if(!empty($f['poc_script_code']))
                                <h4 class="field-subheading">{{ $isEn ? 'Proof of Concept (PoC) Request / Exploit' : 'Bukti Eksploitasi (Proof of Concept)' }}</h4>
                                <pre class="code-block"><code>{{ $f['poc_script_code'] }}</code></pre>
                            @endif

                            <!-- Additional Evidence -->
                            @if(!empty($f['evidence']) && $f['evidence'] !== ($f['poc_description'] ?? ''))
                                <h4 class="field-subheading">{{ $isEn ? 'Observed System Evidence' : 'Bukti Temuan Sistem' }}</h4>
                                <pre class="code-block"><code>{{ $f['evidence'] }}</code></pre>
                            @endif

                            <!-- Remediation Guidance -->
                            @if(!empty($remediation))
                                <div class="remediation-box">
                                    <h5>{{ $isEn ? 'Remediation & Action Plan' : 'Rekomendasi Perbaikan & Mitigasi' }}</h5>
                                    <p>{{ $remediation }}</p>
                                </div>
                            @endif
                        </div>
                    </article>
                @empty
                    <p style="color: var(--c-subtle); font-style: italic;">
                        {{ $isEn ? 'No individual vulnerability reports generated.' : 'Tidak ada laporan kerentanan spesifik yang dihasilkan.' }}
                    </p>
                @endforelse
            </section>

            <!-- 6. LEGAL NOTICE & SIGN-OFF -->
            <section class="disclaimer-card">
                <strong>{{ $isEn ? 'Confidentiality Notice & Disclaimer' : 'Pernyataan Kerahasiaan & Batasan Tanggung Jawab' }}:</strong>
                <p style="margin-top: 6px;">
                    {{ $isEn
                        ? 'This penetration testing report contains highly confidential and sensitive information regarding potential security weaknesses in the target environment. It is intended solely for authorized personnel. Unauthorized distribution, copying, or dissemination of this document is strictly prohibited. The assessment reflects the security posture at the specific time of testing; continuous monitoring and verification of fixes are strongly advised.'
                        : 'Laporan asesmen keamanan ini memuat data yang sangat rahasia mengenai potensi kelemahan keamanan pada target yang diuji. Dokumen ini hanya diperuntukkan bagi personel yang berwenang. Penyebarluasan tanpa izin dilarang keras. Hasil audit mencerminkan kondisi keamanan pada saat pengujian berlangsung; disarankan untuk melakukan pengujian ulang (re-testing) pasca implementasi mitigasi.'
                    }}
                </p>
                <div style="margin-top: 14px; font-family: var(--font-mono); font-size: 11px; color: var(--c-subtle);">
                    {{ $isEn ? 'Verified and signed by Pentesin Autonomous Assessment Pipeline' : 'Divalidasi dan ditandatangani oleh Pentesin Autonomous Assessment Pipeline' }} · {{ $dateStr }}
                </div>
            </section>

        </article>
    </main>

    <!-- Modern AI Synthesis Loading Modal -->
    <dialog id="ai-loading-modal" class="ai-loading-modal" aria-labelledby="ai-modal-title">
        <div class="ai-modal-box">
            <div class="ai-cyber-orb">
                <div class="orb-pulse-ring ring-1"></div>
                <div class="orb-pulse-ring ring-2"></div>
                <div class="orb-core">
                    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
                    </svg>
                </div>
            </div>

            <h3 id="ai-modal-title" class="ai-modal-title">{{ $isEn ? 'AI Security Report Synthesis' : 'Sintesis Narasi Laporan Keamanan AI' }}</h3>
            <p id="ai-modal-subtitle" class="ai-modal-subtitle">{{ $isEn ? 'Harmonizing technical findings with HackerOne VRT & BSSN standards...' : 'Menyelaraskan temuan teknis dengan standar internasional HackerOne VRT & BSSN...' }}</p>

            <div class="ai-steps-list">
                <div class="ai-step-item is-active" id="step-1">
                    <span class="step-indicator"><span class="step-spinner"></span></span>
                    <span class="step-label">{{ $isEn ? 'Extracting vulnerability evidence & root cause' : 'Menganalisis bukti teknis & akar masalah temuan' }}</span>
                </div>
                <div class="ai-step-item" id="step-2">
                    <span class="step-indicator"><span class="step-dot"></span></span>
                    <span class="step-label">{{ $isEn ? 'Synthesizing HackerOne VRT & PTES remediation plans' : 'Menyusun rekomendasi mitigasi standar HackerOne & PTES' }}</span>
                </div>
                <div class="ai-step-item" id="step-3">
                    <span class="step-indicator"><span class="step-dot"></span></span>
                    <span class="step-label">{{ $isEn ? 'Generating bilingual publication narratives (ID / EN)' : 'Menghasilkan narasi dwibahasa profesional (ID / EN)' }}</span>
                </div>
            </div>

            <div class="ai-progress-track">
                <div class="ai-progress-bar" id="ai-progress-bar"></div>
            </div>

            <div class="ai-modal-footer">
                <span class="ai-modal-tip" id="ai-modal-tip">{{ $isEn ? 'Estimated time: 30–60s · Processing in background' : 'Estimasi waktu: 30–60 dtk · Sedang diproses di latar belakang' }}</span>
            </div>
        </div>
    </dialog>

    <script>
        const btnSynthesize = document.getElementById('btn-synthesize');
        const aiModal = document.getElementById('ai-loading-modal');
        const progressBar = document.getElementById('ai-progress-bar');
        const step1 = document.getElementById('step-1');
        const step2 = document.getElementById('step-2');
        const step3 = document.getElementById('step-3');

        function setStepDone(stepEl) {
            stepEl.classList.remove('is-active');
            stepEl.classList.add('is-done');
            stepEl.querySelector('.step-indicator').innerHTML = '<svg class="step-check-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        }

        function setStepActive(stepEl) {
            stepEl.classList.add('is-active');
            stepEl.querySelector('.step-indicator').innerHTML = '<span class="step-spinner"></span>';
        }

        if (btnSynthesize && aiModal) {
            btnSynthesize.addEventListener('click', async () => {
                const btnText = document.getElementById('btn-synthesize-text');
                const originalText = btnText.textContent;
                btnSynthesize.disabled = true;
                btnSynthesize.classList.add('is-loading');

                // Open modern clean popup
                aiModal.showModal();
                progressBar.style.width = '15%';

                let progress = 15;
                const progressInterval = setInterval(() => {
                    if (progress < 92) {
                        progress += Math.random() * 4 + 1.5;
                        progressBar.style.width = Math.min(progress, 92) + '%';
                    }
                }, 1200);

                const step2Timer = setTimeout(() => {
                    setStepDone(step1);
                    setStepActive(step2);
                }, 7000);

                const step3Timer = setTimeout(() => {
                    setStepDone(step2);
                    setStepActive(step3);
                }, 18000);

                try {
                    const response = await fetch('{{ route("scans.report.synthesize", $scan) }}', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Accept': 'application/json',
                            'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
                        },
                    });

                    clearInterval(progressInterval);
                    clearTimeout(step2Timer);
                    clearTimeout(step3Timer);

                    let data = {};
                    try {
                        data = await response.json();
                    } catch (_) {}

                    if (!response.ok || !data.success) {
                        throw new Error(data.error || ('HTTP ' + response.status + ': Gagal memparafrase laporan.'));
                    }

                    // Success animation
                    setStepDone(step1);
                    setStepDone(step2);
                    setStepDone(step3);
                    progressBar.style.width = '100%';
                    document.getElementById('ai-modal-title').textContent = '{{ $isEn ? "Synthesis Complete!" : "Sintesis Selesai!" }}';
                    document.getElementById('ai-modal-subtitle').textContent = '{{ $isEn ? "Reloading updated assessment report..." : "Memperbarui tampilan dokumen laporan..." }}';

                    setTimeout(() => {
                        window.location.reload();
                    }, 800);
                } catch (err) {
                    clearInterval(progressInterval);
                    clearTimeout(step2Timer);
                    clearTimeout(step3Timer);
                    aiModal.close();
                    alert('Gagal: ' + err.message);
                    btnSynthesize.disabled = false;
                    btnSynthesize.classList.remove('is-loading');
                    btnText.textContent = originalText;
                }
            });
        }
    </script>
</body>
</html>
