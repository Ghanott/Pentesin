<x-layout title="Riwayat Pemindaian">
    <div class="history-page">
        <header class="history-head">
            <div class="history-head-text">
                <h1>Riwayat pemindaian</h1>
                <p>Semua pemindaian web dan API yang pernah dijalankan.</p>
            </div>
            <a class="btn-secondary" href="{{ route('dashboard') }}">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                <span>Pemindaian baru</span>
            </a>
        </header>

        @if($scans->isEmpty())
            <div class="empty-scan">
                <svg class="empty-scan-icon" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <circle cx="12" cy="12" r="10"></circle>
                    <polyline points="12 6 12 12 16 14"></polyline>
                </svg>
                <h2>Belum ada pemindaian</h2>
                <p>Jalankan pemindaian pertama. Hasil, temuan, dan laporannya akan muncul di sini.</p>
                <a class="btn-primary" href="{{ route('dashboard') }}">Mulai pemindaian</a>
            </div>
        @else
            <div class="table-card">
                <table class="scan-table">
                    <caption class="sr-only">Riwayat pemindaian, {{ $scans->total() }} entri</caption>
                    <thead>
                        <tr>
                            <th scope="col" class="col-target">Target</th>
                            <th scope="col" class="col-status">Status</th>
                            <th scope="col" class="col-mode">Mode</th>
                            <th scope="col" class="col-findings">Temuan</th>
                            <th scope="col" class="col-time">Waktu</th>
                            <th scope="col" class="col-actions">Tindakan</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($scans as $scan)
                            @php
                                $statusLabels = ['queued'=>'Antrean','running'=>'Berjalan','completed'=>'Selesai','stopped'=>'Dihentikan','failed'=>'Gagal','interrupted'=>'Terputus'];
                                $modeLabels = ['quick'=>'Cepat','standard'=>'Standar','deep'=>'Mendalam'];
                                $findingCount = is_array($scan->findings) ? count($scan->findings) : 0;
                            @endphp
                            <tr>
                                <td class="col-target">
                                    <a class="cell-target" href="{{ route('scans.show', $scan) }}">{{ $scan->target }}</a>
                                </td>
                                <td class="col-status">
                                    <span class="status-badge" data-status="{{ $scan->status }}">
                                        <span class="status-dot" aria-hidden="true"></span>
                                        {{ $statusLabels[$scan->status] ?? $scan->status }}
                                    </span>
                                </td>
                                <td class="col-mode">{{ $modeLabels[$scan->mode] ?? $scan->mode }}</td>
                                <td class="col-findings">
                                    @if($findingCount > 0)
                                        <span class="finding-count">{{ $findingCount }}</span>
                                    @else
                                        <span class="cell-empty">—</span>
                                    @endif
                                </td>
                                <td class="col-time">{{ $scan->created_at->locale('id')->diffForHumans() }}</td>
                                <td class="col-actions">
                                    <div class="row-actions">
                                        <a class="btn-row" href="{{ route('scans.show', $scan) }}">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                                            <span>Buka</span>
                                        </a>

                                        @if($scan->active())
                                            <span class="btn-row is-disabled" title="Hentikan pemindaian sebelum menghapus">
                                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                                                <span>Hapus</span>
                                            </span>
                                        @else
                                            <form method="POST" action="{{ route('scans.destroy', $scan) }}" data-confirm="Hapus pemindaian {{ $scan->target }}? Laporan dan artefaknya ikut terhapus.">
                                                @csrf
                                                @method('DELETE')
                                                <button type="submit" class="btn-row is-danger">
                                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                                                    <span>Hapus</span>
                                                </button>
                                            </form>
                                        @endif
                                    </div>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>

            @if($scans->hasPages())
                <div class="history-pagination">{{ $scans->links() }}</div>
            @endif
        @endif
    </div>
</x-layout>
