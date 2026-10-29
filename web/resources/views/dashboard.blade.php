<x-layout title="Pemindaian">
    <div class="scan-launch-page">
        <header class="launch-heading">
            <div><h1>Pemindaian</h1><p>Tentukan target dan ruang lingkup pengujian.</p></div>
            <a class="button secondary" href="{{ route('scans.history') }}">Riwayat pemindaian</a>
        </header>
        <livewire:scan-form />
    </div>
</x-layout>
