<x-layout title="Konfigurasi LLM">
    <div class="settings-page">
        <header class="settings-head">
            <div class="settings-head-text">
                <h1>Konfigurasi LLM</h1>
                <p>Koneksi model yang dipakai saat menjalankan pemindaian.</p>
            </div>
        </header>

        <div class="settings-grid">
            <section class="settings-card">
                <header class="card-head">
                    <h2>Koneksi baru</h2>
                    <p>API key disimpan terenkripsi dan tidak pernah ditampilkan kembali.</p>
                </header>

                <form method="POST" action="{{ route('profiles.store') }}" class="profile-form">
                    @csrf

                    <div class="field">
                        <label for="new-name">Nama koneksi</label>
                        <input id="new-name" name="name" type="text" required maxlength="120" value="{{ old('name') }}" placeholder="Contoh: GPT-4o produksi" autocomplete="off">
                        <p class="field-hint">Nama ini yang muncul saat memilih profil di halaman pemindaian.</p>
                    </div>

                    <div class="field">
                        <label for="new-url">URL API</label>
                        <input id="new-url" name="api_base" type="url" required maxlength="2048" value="{{ old('api_base') }}" placeholder="https://api.openai.com/v1" autocomplete="off" spellcheck="false" class="input-mono">
                        <p class="field-hint">Endpoint OpenAI-compatible, termasuk <code>/v1</code>.</p>
                    </div>

                    <div class="field">
                        <label for="new-key">API key</label>
                        <input id="new-key" name="api_key" type="password" autocomplete="new-password" maxlength="4096" placeholder="sk-...">
                        <p class="field-hint">Dikosongkan jika endpoint tidak memerlukan key.</p>
                    </div>

                    <div class="field">
                        <label for="new-model">Model</label>
                        <input id="new-model" name="model" type="text" required maxlength="200" value="{{ old('model') }}" placeholder="gpt-4o" autocomplete="off" spellcheck="false" class="input-mono">
                        <p class="field-hint">Nama model persis seperti yang diterima provider.</p>
                    </div>

                    <button class="btn-primary" type="submit">Simpan koneksi</button>
                </form>
            </section>

            <section class="settings-list">
                <header class="list-head">
                    <h2>Koneksi tersimpan</h2>
                    <p>Tes mengirim satu prompt pendek. Perubahan berlaku untuk pemindaian berikutnya.</p>
                </header>

                @forelse($profiles as $profile)
                    <article class="profile-card">
                        <div class="profile-top">
                            <div class="profile-identity">
                                <h3>{{ $profile->name }}</h3>
                                <span class="profile-model">{{ $profile->model }}</span>
                            </div>
                            <span class="key-tag">{{ $profile->has_key ? 'Key tersimpan' : 'Tanpa key' }}</span>
                        </div>

                        <p class="profile-endpoint">{{ $profile->api_base ?: 'Endpoint bawaan provider' }}</p>

                        <div class="profile-actions">
                            <form method="POST" action="{{ route('profiles.test', $profile->id) }}" data-model-test class="test-form">
                                @csrf
                                <button class="btn-row" type="submit">Tes koneksi</button>
                                <span class="connection-result" data-test-status role="status" aria-live="polite"></span>
                            </form>

                            <form method="POST" action="{{ route('profiles.destroy', $profile->id) }}" data-confirm="Hapus koneksi ini? Pemindaian yang sudah dibuat tetap memakai konfigurasi awalnya.">
                                @csrf
                                @method('DELETE')
                                <button type="submit" class="btn-row is-danger">Hapus</button>
                            </form>
                        </div>

                        <details class="profile-edit">
                            <summary>Edit koneksi</summary>
                            <form method="POST" action="{{ route('profiles.update', $profile->id) }}" class="profile-form">
                                @csrf
                                @method('PUT')

                                <div class="field">
                                    <label for="name-{{ $profile->id }}">Nama koneksi</label>
                                    <input id="name-{{ $profile->id }}" name="name" type="text" required maxlength="120" value="{{ $profile->name }}">
                                </div>

                                <div class="field">
                                    <label for="url-{{ $profile->id }}">URL API</label>
                                    <input id="url-{{ $profile->id }}" name="api_base" type="url" required maxlength="2048" value="{{ $profile->api_base }}" class="input-mono">
                                </div>

                                <div class="field">
                                    <label for="key-{{ $profile->id }}">API key</label>
                                    <input id="key-{{ $profile->id }}" name="api_key" type="password" autocomplete="new-password" maxlength="4096" placeholder="Kosongkan untuk mempertahankan key lama">
                                </div>

                                <div class="field">
                                    <label for="model-{{ $profile->id }}">Model</label>
                                    <input id="model-{{ $profile->id }}" name="model" type="text" required maxlength="200" value="{{ $profile->model }}" class="input-mono">
                                </div>

                                <button class="btn-secondary" type="submit">Simpan perubahan</button>
                            </form>
                        </details>
                    </article>
                @empty
                    <div class="empty-profile">
                        <h3>Belum ada koneksi</h3>
                        <p>Tambahkan nama, URL API, key, dan model lewat form di samping.</p>
                    </div>
                @endforelse
            </section>
        </div>
    </div>
</x-layout>
