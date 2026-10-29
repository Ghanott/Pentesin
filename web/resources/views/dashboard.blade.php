<x-layout title="Pemindaian">
    <div class="scan-launch-page">
        <header class="launch-heading">
            <div class="launch-heading-text">
                <h1>Pemindaian</h1>
                <p>Tentukan target dan ruang lingkup pengujian keamanan.</p>
            </div>
            <a class="launch-history-link" href="{{ route('scans.history') }}">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                <span>Riwayat pemindaian</span>
            </a>
        </header>
        <livewire:scan-form />
    </div>
</x-layout>
