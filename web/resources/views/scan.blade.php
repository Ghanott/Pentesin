<x-layout title="Scan live">
    <div id="scan-workspace" data-feed="{{ route('scans.feed', $scan) }}" data-messages="{{ route('scans.messages', $scan) }}" data-status="{{ $scan->status }}">
        <div class="scan-heading"><div><a class="back-link" href="{{ route('scans.history') }}">Riwayat pemindaian</a><h1>{{ $scan->target ?: 'Tes koneksi LLM' }}</h1><div class="scan-meta"><span class="status-pill" id="scan-status" data-status="{{ $scan->status }}">{{ $scan->status }}</span><span>{{ $scan->mode ?? 'model test' }}</span><span class="mono">{{ $scan->id }}</span></div></div>
            @foreach($artifacts as $artifact)<a class="button secondary" href="{{ route('scans.artifacts', [$scan, $artifact]) }}">Unduh {{ $artifact }}</a>@endforeach
            @if(in_array($scan->status, ['queued', 'running']))<form method="POST" action="{{ route('scans.stop', $scan) }}" data-confirm="Hentikan pemindaian ini? Sandbox akan dibersihkan sebelum status dihentikan.">@csrf<button type="submit" class="button danger">Hentikan scan</button></form>@endif
        </div>
        <div id="connection-status" class="connection-status" role="status">Menghubungkan ke aktivitas runner…</div>
        <div id="scan-error" class="notice error" role="alert" hidden></div>
        <div class="live-layout">
            <section class="panel graph-panel" aria-labelledby="graph-title"><header class="panel-heading"><div><h2 id="graph-title">Peta pengujian</h2></div><div class="graph-controls"><button class="icon-button" id="graph-fit" aria-label="Tampilkan seluruh graph">⊞</button><button class="icon-button" id="graph-zoom-in" aria-label="Perbesar graph">+</button><button class="icon-button" id="graph-zoom-out" aria-label="Perkecil graph">−</button></div></header>
                <div class="graph-stage"><div id="agent-graph" aria-label="Graph hubungan agent"></div><div class="graph-empty" id="graph-empty"><h3>Menunggu agent pertama</h3><p>Graph muncul setelah runner memulai pengujian.</p></div></div>
                <footer class="graph-legend"><span><i class="legend-marker running"></i>Berjalan</span><span><i class="legend-marker waiting"></i>Menunggu</span><span><i class="legend-marker completed"></i>Selesai</span><span><i class="legend-marker failed"></i>Gagal</span><span class="graph-tip">Klik agent untuk membuka aktivitas & chat</span></footer>
            </section>
            <aside class="panel run-detail"><h2>Instruksi Anda</h2><p class="instruction-text">{{ $scan->instruction ?: 'Tidak ada instruksi tambahan.' }}</p><hr><div class="detail-row"><span>Agent</span><strong id="agent-count">0</strong></div><div class="detail-row"><span>Temuan</span><strong id="finding-count">0</strong></div><div class="detail-row"><span>Tahap</span><strong id="scan-phase">{{ $scan->phase ?: 'Menunggu runner' }}</strong></div><p class="fine-print">Instruksi baru tidak memperluas cakupan target. Riwayat tetap tersimpan saat halaman ditutup.</p></aside>
        </div>
        <section class="panel agent-list-panel"><details><summary>Daftar agent · navigasi keyboard</summary><div id="agent-list" class="agent-list"><p class="muted">Belum ada agent.</p></div></details></section>
        <section class="findings-section"><div class="section-heading"><div><h2>Temuan kerentanan</h2><p>Kandidat baru ditampilkan setelah dilaporkan oleh engine.</p></div></div><div id="findings" class="findings-list"><div class="empty-state panel"><h3>Belum ada temuan.</h3><p>Ini bukan pernyataan bahwa target aman.</p></div></div><div id="scan-artifacts" class="artifact-list" aria-label="Laporan pemindaian"></div></section>
        <div id="model-test-result" class="panel test-result" hidden><h2>Hasil tes model</h2><div class="model-test-grid"><div><span class="eyebrow">KONEKSI</span><strong data-test="connection">—</strong></div><div><span class="eyebrow">LATENSI</span><strong data-test="latency_ms">—</strong></div></div><p data-test="error" role="status"></p></div>
    </div>
    <dialog id="agent-modal" class="agent-modal" aria-labelledby="agent-modal-title">
        <header class="modal-heading"><div><h2 id="agent-modal-title">Aktivitas agent</h2><span class="muted" id="agent-modal-status"></span></div><button class="icon-button" data-close-dialog aria-label="Tutup aktivitas agent">×</button></header>
        <div class="terminal-toolbar"><span class="console-channel"><span class="console-dot" aria-hidden="true"></span>Aktivitas langsung</span><button class="text-button" id="scroll-latest">Aktivitas terbaru</button></div>
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
    <dialog id="finding-modal" class="finding-modal" aria-labelledby="finding-modal-title"><header class="modal-heading"><div><span class="eyebrow">LAPORAN KERENTANAN</span><h2 id="finding-modal-title"></h2></div><button class="icon-button" data-close-dialog aria-label="Tutup laporan">×</button></header><div id="finding-detail" class="finding-detail"></div></dialog>
</x-layout>
