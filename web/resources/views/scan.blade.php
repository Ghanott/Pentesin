<x-layout title="Detail Pemindaian">
    <div id="scan-workspace" class="scan-detail" data-feed="{{ route('scans.feed', $scan) }}" data-messages="{{ route('scans.messages', $scan) }}" data-status="{{ $scan->status }}">
        <header class="detail-head">
            <div class="detail-head-main">
                <a class="back-link" href="{{ route('scans.history') }}">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="15 18 9 12 15 6"></polyline></svg>
                    <span>Riwayat pemindaian</span>
                </a>

                <h1 class="detail-target">{{ $scan->target ?: 'Tes koneksi LLM' }}</h1>

                <div class="detail-meta">
                    <span class="status-badge" id="scan-status" data-status="{{ $scan->status }}">
                        <span class="status-dot" aria-hidden="true"></span>
                        <span id="scan-status-label">{{ ['queued'=>'Antrean','running'=>'Berjalan','completed'=>'Selesai','stopped'=>'Dihentikan','failed'=>'Gagal','interrupted'=>'Terputus'][$scan->status] ?? $scan->status }}</span>
                    </span>
                    <span class="meta-chip">{{ ['quick'=>'Cepat','standard'=>'Standar','deep'=>'Mendalam'][$scan->mode] ?? ($scan->mode ?? 'model test') }}</span>
                    <span class="meta-time">{{ $scan->created_at->locale('id')->diffForHumans() }}</span>
                </div>
            </div>

            <div class="detail-head-actions">
                <div id="scan-artifacts" class="report-row" aria-label="Laporan pemindaian">
                    @foreach($artifacts as $artifact)
                        <a class="report-btn" href="{{ route('scans.artifacts', [$scan, $artifact]) }}">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                            <span>{{ $artifact }}</span>
                        </a>
                        @if($artifact === 'vulnerabilities.json')
                            <a class="report-btn is-pdf" href="{{ route('scans.report', $scan) }}" target="_blank" rel="noopener" title="Lihat dan cetak Laporan PDF (Standar HackerOne / PTES)">
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
                                <span>Laporan PDF</span>
                            </a>
                        @endif
                    @endforeach
                    @if(!in_array('vulnerabilities.json', $artifacts) && (count($scan->findings ?? []) > 0 || in_array($scan->status, ['completed', 'stopped'])))
                        <a class="report-btn is-pdf" href="{{ route('scans.report', $scan) }}" target="_blank" rel="noopener" title="Lihat dan cetak Laporan PDF (Standar HackerOne / PTES)">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
                            <span>Laporan PDF</span>
                        </a>
                    @endif
                </div>

                @if(in_array($scan->status, ['queued', 'running']))
                    <form method="POST" action="{{ route('scans.stop', $scan) }}" data-confirm="Hentikan pemindaian ini? Sandbox akan dibersihkan sebelum status dihentikan.">
                        @csrf
                        <button type="submit" class="btn-row is-danger">Hentikan pemindaian</button>
                    </form>
                @endif
            </div>
        </header>

        <p id="connection-status" class="conn-line" role="status">Menghubungkan ke aktivitas runner…</p>
        <div id="scan-error" class="notice error" role="alert" hidden></div>

        <div class="detail-grid">
            <section class="graph-card" aria-labelledby="graph-title">
                <header class="graph-card-head">
                    <h2 id="graph-title">Peta agent</h2>
                    <div class="graph-controls">
                        <button class="icon-btn" id="graph-fit" aria-label="Tampilkan seluruh graph" title="Muat ulang tampilan">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 8V5a2 2 0 0 1 2-2h3"></path><path d="M21 8V5a2 2 0 0 0-2-2h-3"></path><path d="M3 16v3a2 2 0 0 0 2 2h3"></path><path d="M21 16v3a2 2 0 0 1-2 2h-3"></path></svg>
                        </button>
                        <button class="icon-btn" id="graph-zoom-in" aria-label="Perbesar graph" title="Perbesar">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                        </button>
                        <button class="icon-btn" id="graph-zoom-out" aria-label="Perkecil graph" title="Perkecil">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                        </button>
                    </div>
                </header>

                <div class="graph-stage">
                    <div id="agent-graph" aria-label="Graph hubungan agent"></div>
                    <div class="graph-empty" id="graph-empty">
                        <h3>Menunggu agent pertama</h3>
                        <p>Peta muncul setelah runner memulai pengujian.</p>
                    </div>
                </div>

                <footer class="graph-legend">
                    <span><i class="legend-marker running"></i>Berjalan</span>
                    <span><i class="legend-marker waiting"></i>Menunggu</span>
                    <span><i class="legend-marker completed"></i>Selesai</span>
                    <span><i class="legend-marker failed"></i>Gagal</span>
                    <span class="graph-tip">Klik agent untuk membuka aktivitas</span>
                </footer>
            </section>

            <aside class="detail-side">
                <section class="side-card">
                    <h2>Ringkasan</h2>
                    <dl class="stat-list">
                        <div class="stat-row"><dt>Agent</dt><dd id="agent-count">0</dd></div>
                        <div class="stat-row"><dt>Temuan</dt><dd id="finding-count">0</dd></div>
                        <div class="stat-row"><dt>Tahap</dt><dd id="scan-phase">{{ $scan->phase ?: 'Menunggu runner' }}</dd></div>
                    </dl>
                </section>

                <section class="side-card">
                    <h2>Instruksi</h2>
                    <p class="side-instruction">{{ $scan->instruction ?: 'Tidak ada instruksi tambahan.' }}</p>
                </section>

                <section class="side-card">
                    <header class="side-card-head">
                        <h2>Daftar agent</h2>
                        <span class="side-count" id="agent-list-count">0</span>
                    </header>
                    <div id="agent-list" class="agent-list">
                        <p class="side-empty">Belum ada agent.</p>
                    </div>
                </section>
            </aside>
        </div>

        <section class="findings-section">
            <header class="section-head">
                <h2>Temuan kerentanan</h2>
                <p>Kandidat ditampilkan setelah dilaporkan oleh engine. Daftar kosong bukan berarti target aman.</p>
            </header>
            <div id="findings" class="findings-list">
                <div class="empty-findings">
                    <h3>Belum ada temuan</h3>
                    <p>Temuan akan muncul di sini saat agent melaporkannya.</p>
                </div>
            </div>
        </section>

        <div id="model-test-result" class="test-result-card" hidden>
            <h2>Hasil tes model</h2>
            <div class="test-grid">
                <div><span class="test-label">Koneksi</span><strong data-test="connection">—</strong></div>
                <div><span class="test-label">Latensi</span><strong data-test="latency_ms">—</strong></div>
            </div>
            <p data-test="error" role="status"></p>
        </div>
    </div>

    <dialog id="agent-modal" class="agent-modal" aria-labelledby="agent-modal-title">
        <header class="modal-heading">
            <div class="modal-title-group">
                <h2 id="agent-modal-title">Aktivitas agent</h2>
                <span class="agent-modal-badge" id="agent-modal-status"></span>
            </div>
            <button class="icon-btn modal-close" data-close-dialog aria-label="Tutup aktivitas agent">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
        </header>
        <div class="terminal-toolbar">
            <span class="console-channel"><span class="console-dot" aria-hidden="true"></span>Aktivitas langsung</span>
            <button class="text-button" id="scroll-latest">Aktivitas terbaru</button>
        </div>
        <div id="agent-transcript" class="transcript" tabindex="0" aria-label="Riwayat aktivitas agent"></div>
        <footer class="chat-footer">
            <form id="agent-message-form">
                <div class="composer-heading">
                    <label for="agent-message">Instruksi untuk agent</label>
                    <span id="message-shortcuts" class="composer-shortcuts"><kbd>Enter</kbd> kirim · <kbd>Shift + Enter</kbd> baris baru</span>
                </div>
                <div class="chat-input"><textarea id="agent-message" name="message" maxlength="4000" rows="2" required aria-describedby="message-shortcuts message-status" placeholder="Tanya hasil, arahkan pengujian, atau beri konteks tambahan…"></textarea></div>
                <p id="message-status" class="muted" role="status">Pesan diteruskan ke mailbox agent.</p>
            </form>
        </footer>
    </dialog>

    <dialog id="finding-modal" class="finding-modal" aria-labelledby="finding-modal-title">
        <header class="modal-heading">
            <div>
                <h2 id="finding-modal-title"></h2>
            </div>
            <button class="icon-btn modal-close" data-close-dialog aria-label="Tutup laporan">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
        </header>
        <div id="finding-detail" class="finding-detail"></div>
    </dialog>
</x-layout>
