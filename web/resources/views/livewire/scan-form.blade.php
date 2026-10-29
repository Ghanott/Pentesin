<section class="scan-launch" aria-labelledby="new-scan-title">
    <div class="launch-main">
        <header class="launch-section-heading"><h2 id="new-scan-title">Pemindaian baru</h2><span class="launch-badge">Black-box</span></header>
        <form method="POST" action="{{ route('scans.store') }}">
            @csrf
            <div class="field target-field"><label for="target">Target pengujian</label><input id="target" name="target" type="text" required maxlength="2048" placeholder="https://lab.example.com" value="{{ old('target') }}" autocomplete="off" spellcheck="false"><small>Domain, URL, atau alamat IP yang diizinkan untuk diuji.</small></div>
            <div class="field"><label for="instruction">Instruksi pengujian <span class="optional-label">Opsional</span></label><textarea id="instruction" name="instruction" rows="5" maxlength="10000" placeholder="Jelaskan fokus pengujian, area yang dikecualikan, dan batasan yang harus dipatuhi.">{{ old('instruction') }}</textarea></div>
            <div class="launch-options">
                <div class="field"><label for="mode">Kedalaman pengujian</label><select id="mode" name="mode">@foreach(['standard' => 'Standar', 'deep' => 'Mendalam'] as $value => $label)<option value="{{ $value }}" @selected(old('mode', 'standard') === $value)>{{ $label }}</option>@endforeach</select><small>Sesuaikan dengan cakupan dan waktu yang tersedia.</small></div>
                <div class="field"><label for="profile">Profil model</label><select id="profile" name="llm_profile_id" required><option value="">Pilih profil model</option>@foreach($profiles as $profile)<option value="{{ $profile->id }}" @selected((string) old('llm_profile_id') === (string) $profile->id)>{{ $profile->name }} · {{ $profile->model }}</option>@endforeach</select><small>Kelola koneksi di <a href="{{ route('settings') }}">pengaturan</a>.</small></div>
            </div>
            <label class="launch-context" for="context-mode"><span><strong>Context Mode <span class="launch-beta">Eksperimental</span></strong><small>Analisis output panjang dan cari kembali bukti di sandbox scan.</small></span><input id="context-mode" type="checkbox" name="context_mode" value="1" @checked(old('context_mode'))></label>
            <footer class="launch-submit"><p>Pemindaian berjalan di sandbox terisolasi.</p><button class="button primary" type="submit" @disabled($profiles->isEmpty())>Mulai pemindaian</button></footer>
            @if($profiles->isEmpty())<p class="inline-warning">Tambahkan <a href="{{ route('settings') }}">profil model</a> sebelum memulai.</p>@endif
        </form>
    </div>
    <aside class="launch-guide" aria-label="Panduan pemindaian">
        <h2>Sebelum memulai</h2>
        <section><h3>Pastikan izin pengujian</h3><p>Masukkan hanya target yang termasuk dalam ruang lingkup izin Anda.</p></section>
        <section><h3>Tulis batasan dengan jelas</h3><p>Sebutkan akun uji, endpoint yang dikecualikan, dan tindakan yang tidak diperbolehkan.</p></section>
        <section><h3>Pantau pekerjaan agent</h3><p>Buka console agent untuk membaca aktivitas dan mengirim arahan selama pemindaian.</p></section>
        <div class="launch-guide-note"><span class="status-dot" aria-hidden="true"></span><p>Satu pemindaian aktif. Pemindaian berikutnya menunggu di antrean.</p></div>
    </aside>
</section>
