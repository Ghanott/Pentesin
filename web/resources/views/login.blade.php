<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Masuk · Pentesin</title>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
    <style>
        :root {
            --bg-base: #080d14;
            --bg-card: rgba(15, 23, 34, 0.78);
            --bg-input: rgba(10, 16, 24, 0.85);
            --border-subtle: rgba(255, 255, 255, 0.08);
            --border-focus: #53d4c3;
            --text-main: #f0f4f8;
            --text-muted: #8b9baa;
            --text-subtle: #576778;
            --accent: #53d4c3;
            --accent-hover: #6ee7d7;
            --accent-ink: #061815;
            --danger-bg: rgba(239, 68, 68, 0.1);
            --danger-border: rgba(239, 68, 68, 0.25);
            --danger-text: #fca5a5;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body.login-body {
            min-height: 100vh;
            min-height: 100dvh;
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: 'Poppins', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px 16px;
            position: relative;
            overflow-x: hidden;
        }

        /* Ambient background glow & grid */
        .login-ambient {
            position: fixed;
            inset: 0;
            pointer-events: none;
            z-index: 0;
            overflow: hidden;
        }

        .ambient-glow {
            position: absolute;
            top: -150px;
            left: 50%;
            transform: translateX(-50%);
            width: 720px;
            height: 480px;
            background: radial-gradient(circle, rgba(83, 212, 195, 0.12) 0%, rgba(83, 212, 195, 0.02) 45%, transparent 70%);
            filter: blur(50px);
        }

        .ambient-grid {
            position: absolute;
            inset: 0;
            background-image: radial-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px);
            background-size: 28px 28px;
            mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, #000 30%, transparent 85%);
            -webkit-mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, #000 30%, transparent 85%);
        }

        /* Container & Card */
        .login-container {
            width: 100%;
            max-width: 400px;
            position: relative;
            z-index: 1;
        }

        .login-card-modern {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border-subtle);
            border-radius: 18px;
            padding: 36px 32px;
            box-shadow: 0 24px 48px -12px rgba(0, 0, 0, 0.65), 0 0 0 1px rgba(255, 255, 255, 0.03) inset;
        }

        /* Brand & Header */
        .brand-header {
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            margin-bottom: 28px;
        }

        .brand-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 46px;
            height: 46px;
            border-radius: 12px;
            background: linear-gradient(180deg, rgba(255, 255, 255, 0.07) 0%, rgba(255, 255, 255, 0.02) 100%);
            border: 1px solid rgba(255, 255, 255, 0.12);
            box-shadow: 0 8px 16px -4px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
            margin-bottom: 18px;
            font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
            font-size: 22px;
            font-weight: 700;
            color: var(--text-main);
            position: relative;
        }

        .brand-badge span {
            color: var(--accent);
            margin-left: 1px;
        }

        .login-title {
            font-size: 22px;
            font-weight: 600;
            letter-spacing: -0.03em;
            color: var(--text-main);
            margin-bottom: 6px;
        }

        .login-subtitle {
            font-size: 13px;
            color: var(--text-muted);
            line-height: 1.5;
        }

        /* Error Notice */
        .alert-error {
            background: var(--danger-bg);
            border: 1px solid var(--danger-border);
            border-radius: 10px;
            padding: 12px 14px;
            margin-bottom: 20px;
            color: var(--danger-text);
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 10px;
            line-height: 1.4;
        }

        .alert-error svg {
            flex-shrink: 0;
            stroke: currentColor;
        }

        /* Form Controls */
        .login-form {
            display: flex;
            flex-direction: column;
            gap: 18px;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 7px;
        }

        .form-label {
            font-size: 12px;
            font-weight: 500;
            color: #d1dce7;
            letter-spacing: 0.01em;
        }

        .input-wrapper {
            position: relative;
            display: flex;
            align-items: center;
        }

        .form-input {
            width: 100%;
            height: 44px;
            background: var(--bg-input);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            padding: 0 14px;
            color: var(--text-main);
            font-size: 14px;
            font-family: inherit;
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            outline: none;
        }

        .form-input::placeholder {
            color: var(--text-subtle);
            font-size: 13px;
        }

        .form-input:hover {
            border-color: rgba(255, 255, 255, 0.16);
        }

        .form-input:focus {
            border-color: var(--border-focus);
            background: rgba(14, 21, 31, 0.95);
            box-shadow: 0 0 0 3px rgba(83, 212, 195, 0.15);
        }

        .input-with-icon {
            padding-right: 42px;
        }

        .password-toggle-btn {
            position: absolute;
            right: 10px;
            background: transparent;
            border: 0;
            color: var(--text-subtle);
            width: 28px;
            height: 28px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 6px;
            cursor: pointer;
            transition: color 0.15s ease, background 0.15s ease;
        }

        .password-toggle-btn:hover {
            color: var(--text-main);
            background: rgba(255, 255, 255, 0.05);
        }

        .password-toggle-btn:focus-visible {
            outline: 2px solid var(--accent);
            outline-offset: 2px;
        }

        /* Submit Button */
        .submit-btn {
            height: 44px;
            background: var(--accent);
            color: var(--accent-ink);
            border: none;
            border-radius: 10px;
            font-size: 13.5px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            margin-top: 6px;
            box-shadow: 0 4px 16px -2px rgba(83, 212, 195, 0.25);
        }

        .submit-btn:hover {
            background: var(--accent-hover);
            box-shadow: 0 6px 20px -2px rgba(83, 212, 195, 0.35);
            transform: translateY(-1px);
        }

        .submit-btn:active {
            transform: translateY(0);
            box-shadow: 0 2px 8px -2px rgba(83, 212, 195, 0.2);
        }

        .submit-btn:focus-visible {
            outline: 2px solid var(--accent);
            outline-offset: 3px;
        }

        .submit-btn svg {
            transition: transform 0.2s ease;
        }

        .submit-btn:hover svg {
            transform: translateX(2px);
        }

        /* Footer */
        .login-footer {
            margin-top: 24px;
            text-align: center;
            font-size: 11px;
            color: var(--text-subtle);
            letter-spacing: 0.02em;
        }

        @media (max-width: 480px) {
            .login-card-modern {
                padding: 28px 22px;
                border-radius: 16px;
            }

            .login-title {
                font-size: 20px;
            }
        }
    </style>
</head>
<body class="login-body">
    <div class="login-ambient" aria-hidden="true">
        <div class="ambient-glow"></div>
        <div class="ambient-grid"></div>
    </div>

    <main class="login-container">
        <div class="login-card-modern">
            <header class="brand-header">
                <div class="brand-badge" aria-hidden="true">
                    #p<span>_</span>
                </div>
                <h1 class="login-title">Masuk ke Akun</h1>
                <p class="login-subtitle">Masukkan email dan kata sandi Anda untuk melanjutkan</p>
            </header>

            @if($errors->any())
                <div class="alert-error" role="alert">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="12" y1="8" x2="12" y2="12"></line>
                        <line x1="12" y1="16" x2="12.01" y2="16"></line>
                    </svg>
                    <span>{{ $errors->first() }}</span>
                </div>
            @endif

            <form method="POST" action="{{ route('login') }}" class="login-form">
                @csrf

                <div class="form-group">
                    <label for="email" class="form-label">Email</label>
                    <div class="input-wrapper">
                        <input
                            id="email"
                            name="email"
                            type="email"
                            autocomplete="username"
                            value="{{ old('email') }}"
                            placeholder="nama@email.com"
                            class="form-input"
                            required
                            autofocus
                        >
                    </div>
                </div>

                <div class="form-group">
                    <label for="password" class="form-label">Kata Sandi</label>
                    <div class="input-wrapper">
                        <input
                            id="password"
                            name="password"
                            type="password"
                            autocomplete="current-password"
                            placeholder="••••••••"
                            class="form-input input-with-icon"
                            required
                        >
                        <button
                            type="button"
                            id="togglePassword"
                            class="password-toggle-btn"
                            aria-label="Tampilkan kata sandi"
                            tabindex="-1"
                        >
                            <!-- Eye icon (show) -->
                            <svg id="eyeIcon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                            <!-- Eye-off icon (hide) -->
                            <svg id="eyeOffIcon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: none;">
                                <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"></path>
                                <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"></path>
                                <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"></path>
                                <line x1="2" y1="2" x2="22" y2="22"></line>
                            </svg>
                        </button>
                    </div>
                </div>

                <button type="submit" class="submit-btn">
                    <span>Masuk</span>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M5 12h14"></path>
                        <path d="m12 5 7 7-7 7"></path>
                    </svg>
                </button>
            </form>
        </div>

        <footer class="login-footer">
            <span>&copy; {{ date('Y') }} Pentesin</span>
        </footer>
    </main>

    <script>
        document.addEventListener('DOMContentLoaded', function () {
            const toggleBtn = document.getElementById('togglePassword');
            const passwordInput = document.getElementById('password');
            const eyeIcon = document.getElementById('eyeIcon');
            const eyeOffIcon = document.getElementById('eyeOffIcon');

            if (toggleBtn && passwordInput && eyeIcon && eyeOffIcon) {
                toggleBtn.addEventListener('click', function () {
                    const isPassword = passwordInput.type === 'password';
                    passwordInput.type = isPassword ? 'text' : 'password';
                    eyeIcon.style.display = isPassword ? 'none' : 'block';
                    eyeOffIcon.style.display = isPassword ? 'block' : 'none';
                    toggleBtn.setAttribute('aria-label', isPassword ? 'Sembunyikan kata sandi' : 'Tampilkan kata sandi');
                });
            }
        });
    </script>
</body>
</html>
