<x-layout title="Konfigurasi LLM">
    <div class="page-heading"><div><span class="eyebrow">MODEL WORKSPACE</span><h1>Hubungkan model Anda.</h1><p>Cukup URL API, API key, dan nama model.</p></div></div>
    <div class="notice">URL <code>localhost</code> mengacu pada mesin runner, bukan browser Anda. Tes mengirim satu request chat singkat dan dapat dikenai biaya API.</div>
    <div class="settings-grid">
        <section class="panel">
            <div class="section-heading"><div><h2>Koneksi baru</h2><p>API key dienkripsi dan tidak ditampilkan kembali.</p></div></div>
            <form method="POST" action="{{ route('profiles.store') }}">
                @csrf
                <div class="field"><label for="new-url">URL API</label><input id="new-url" name="api_base" type="url" required maxlength="2048" value="{{ old('api_base') }}" placeholder="http://localhost:20128/v1"></div>
                <div class="field"><label for="new-key">API key</label><input id="new-key" name="api_key" type="password" autocomplete="new-password" maxlength="4096" placeholder="Masukkan API key"></div>
                <div class="field"><label for="new-model">Model</label><input id="new-model" name="model" required maxlength="200" value="{{ old('model') }}" placeholder="hunter"><small>Model OpenAI-compatible dengan Base URL khusus dapat ditulis <code>openai/nama-model</code>.</small></div>
                <button class="button primary" type="submit">Simpan koneksi ↗</button>
            </form>
        </section>
        <section>
            <div class="section-heading"><div><h2>Koneksi tersimpan</h2><p>Tes mengirim prompt “test” dan cek apakah model membalas. Tool calling tidak diuji. Perubahan berlaku untuk scan berikutnya.</p></div></div>
            @forelse($profiles as $profile)
                <article class="panel profile-card">
                    <div class="profile-heading"><div><h3>{{ $profile->model }}</h3><p class="muted profile-url">{{ $profile->api_base ?: 'Endpoint bawaan provider' }}</p></div><span class="outline-tag">Key tersembunyi</span></div>
                    <div class="profile-actions">
                        <form method="POST" action="{{ route('profiles.test', $profile->id) }}" data-model-test>
                            @csrf
                            <button class="button secondary" type="submit">Tes koneksi</button>
                            <p class="connection-result muted" data-test-status role="status" aria-live="polite"></p>
                        </form>
                        <form method="POST" action="{{ route('profiles.destroy', $profile->id) }}" data-confirm="Hapus koneksi ini? Scan yang sudah dibuat tetap memakai konfigurasi awalnya.">@csrf @method('DELETE')<button class="text-button danger-text" type="submit">Hapus</button></form>
                    </div>
                    <details class="profile-edit"><summary>Edit koneksi</summary>
                        <form method="POST" action="{{ route('profiles.update', $profile->id) }}">
                            @csrf @method('PUT')
                            <div class="field"><label for="url-{{ $profile->id }}">URL API</label><input id="url-{{ $profile->id }}" name="api_base" type="url" required maxlength="2048" value="{{ $profile->api_base }}"></div>
                            <div class="field"><label for="key-{{ $profile->id }}">API key</label><input id="key-{{ $profile->id }}" name="api_key" type="password" autocomplete="new-password" maxlength="4096" placeholder="Kosong berarti mempertahankan key lama"></div>
                            <div class="field"><label for="model-{{ $profile->id }}">Model</label><input id="model-{{ $profile->id }}" name="model" required maxlength="200" value="{{ $profile->model }}"></div>
                            <button class="button secondary" type="submit">Simpan perubahan</button>
                        </form>
                    </details>
                </article>
            @empty
                <div class="panel empty-state"><h3>Belum ada koneksi.</h3><p>Tambahkan URL API, key, dan model melalui form di samping.</p></div>
            @endforelse
        </section>
    </div>
</x-layout>
