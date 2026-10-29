<section class="scan-launch" aria-labelledby="new-scan-title">
    <div class="launch-main">
        <header class="launch-section-heading">
            <h2 id="new-scan-title">Pemindaian baru</h2>
            <p class="launch-section-desc">Konfigurasi target dan parameter pengujian.</p>
        </header>

        <form method="POST" action="{{ route('scans.store') }}" class="scan-form-content">
            @csrf

            <div class="field">
                <label for="target">Target pengujian</label>
                <input id="target" name="target" type="text" required maxlength="2048" placeholder="https://target.com" value="{{ old('target') }}" autocomplete="off" spellcheck="false" class="input-mono">
                <p class="field-hint">Domain, URL, atau alamat IP yang diizinkan untuk diuji.</p>
            </div>

            <div class="field">
                <div class="label-row">
                    <label for="instruction">Instruksi pengujian</label>
                    <span class="label-optional">Opsional</span>
                </div>
                <textarea id="instruction" name="instruction" rows="4" maxlength="10000" placeholder="Jelaskan fokus pengujian, area yang dikecualikan, dan batasan yang harus dipatuhi.">{{ old('instruction') }}</textarea>
            </div>

            <div class="field-grid">
                <div class="field">
                    <label for="mode">Kedalaman pengujian</label>
                    <select id="mode" name="mode">
                        @foreach(['standard' => 'Standar', 'deep' => 'Mendalam'] as $value => $label)
                            <option value="{{ $value }}" @selected(old('mode', 'standard') === $value)>{{ $label }}</option>
                        @endforeach
                    </select>
                    <p class="field-hint">Sesuaikan dengan cakupan dan waktu tersedia.</p>
                </div>

                <div class="field">
                    <label for="profile">Profil model</label>
                    <select id="profile" name="llm_profile_id" required>
                        <option value="">Pilih profil model</option>
                        @foreach($profiles as $profile)
                            <option value="{{ $profile->id }}" @selected((string) old('llm_profile_id') === (string) $profile->id)>{{ $profile->name }} · {{ $profile->model }}</option>
                        @endforeach
                    </select>
                    <p class="field-hint">Kelola koneksi di <a href="{{ route('settings') }}">pengaturan</a>.</p>
                </div>
            </div>

            <div class="option-row">
                <div class="option-row-text">
                    <label for="context-mode">Context Mode <span class="tag">Eksperimental</span></label>
                    <p>Optimasi context window: isolasi output tools di sandbox untuk menghemat token dan menjaga memori agent.</p>
                </div>
                <label class="switch" for="context-mode" aria-label="Aktifkan Context Mode">
                    <input id="context-mode" type="checkbox" name="context_mode" value="1" @checked(old('context_mode'))>
                    <span class="switch-track"></span>
                </label>
            </div>

            @if($profiles->isEmpty())
                <p class="form-warning">Belum ada profil model aktif. Tambahkan <a href="{{ route('settings') }}">profil model</a> sebelum memulai.</p>
            @endif

            <footer class="launch-submit">
                <p class="submit-note">Pemindaian berjalan di sandbox terisolasi.</p>
                <button class="btn-primary" type="submit" @disabled($profiles->isEmpty())>Mulai pemindaian</button>
            </footer>
        </form>
    </div>

    <aside class="launch-guide" aria-label="Panduan pemindaian">
        <h2>Sebelum memulai</h2>

        <div class="guide-steps">
            <section>
                <h3>Pastikan izin pengujian</h3>
                <p>Masukkan hanya target yang termasuk dalam ruang lingkup izin Anda.</p>
            </section>

            <section>
                <h3>Tulis batasan dengan jelas</h3>
                <p>Sebutkan akun uji, endpoint yang dikecualikan, dan tindakan yang tidak diperbolehkan.</p>
            </section>

            <section>
                <h3>Pantau pekerjaan agent</h3>
                <p>Buka console agent untuk membaca aktivitas dan mengirim arahan selama pemindaian.</p>
            </section>
        </div>

        <p class="guide-note">Satu pemindaian aktif. Pemindaian berikutnya menunggu di antrean.</p>
    </aside>
</section>
