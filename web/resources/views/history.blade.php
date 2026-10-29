<x-layout title="Riwayat Pemindaian">
    <div class="page-heading">
        <div><span class="eyebrow">PENTESIN / RIWAYAT</span><h1>Riwayat pemindaian</h1><p>Graph agent, aktivitas, dan temuan dari pemindaian web/API Anda.</p></div>
        <a class="button primary" href="{{ route('dashboard') }}">Pemindaian baru ↗</a>
    </div>
    @if($scans->isEmpty())
        <div class="empty-state panel"><span class="empty-symbol" aria-hidden="true">◈</span><h2>Belum ada pemindaian.</h2><p>Tes koneksi LLM tidak dimasukkan ke riwayat ini.</p></div>
    @else
        <div class="section-heading"><span class="muted">{{ $scans->total() }} pemindaian</span></div>
        <div class="table-wrap panel">
            <table>
                <thead><tr><th>Sasaran</th><th>Status</th><th>Mode</th><th>Dibuat</th><th><span class="sr-only">Tindakan</span></th></tr></thead>
                <tbody>
                    @foreach($scans as $scan)
                        <tr>
                            <td><a class="target-link" href="{{ route('scans.show', $scan) }}">{{ $scan->target }}</a><small class="table-subtitle">{{ $scan->id }}</small></td>
                            <td><span class="status-pill" data-status="{{ $scan->status }}">{{ ['queued'=>'Antrean','running'=>'Berjalan','completed'=>'Selesai','stopped'=>'Dihentikan','failed'=>'Gagal','interrupted'=>'Terputus'][$scan->status] ?? $scan->status }}</span></td>
                            <td>{{ $scan->mode }}</td>
                            <td class="muted">{{ $scan->created_at->diffForHumans() }}</td>
                            <td><a class="table-arrow" href="{{ route('scans.show', $scan) }}" aria-label="Buka {{ $scan->target }}">↗</a></td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
        <div class="history-pagination">{{ $scans->links() }}</div>
    @endif
</x-layout>
