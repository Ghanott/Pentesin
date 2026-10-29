@props(['title' => 'Dashboard'])
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ $title }} · Pentesin</title>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
    @livewireStyles
</head>
<body>
    <a class="skip-link" href="#main">Lewati navigasi</a>
    <aside class="navigation">
        <a class="brand" href="{{ route('dashboard') }}"><span class="brand-mark" aria-hidden="true">P<span>_</span></span><span>pentesin<small>PRIVATE WORKSPACE</small></span></a>
        <div class="nav-section">RUANG KERJA</div>
        <nav aria-label="Navigasi utama">
            <a href="{{ route('dashboard') }}" @class(['active' => request()->routeIs('dashboard')])><span aria-hidden="true">◈</span> Pemindaian</a>
            <a href="{{ route('scans.history') }}" @class(['active' => request()->routeIs('scans.*')])><span aria-hidden="true">↺</span> Riwayat Pemindaian</a>
            <a href="{{ route('settings') }}" @class(['active' => request()->routeIs('settings', 'profiles.*')])><span aria-hidden="true">⌘</span> Konfigurasi LLM</a>
        </nav>
        <div class="nav-bottom"><span class="private-badge">Akses privat</span><p>Web & API · black-box only</p>
            <form method="POST" action="{{ route('logout') }}">@csrf<button class="text-button" type="submit">Keluar dari workspace</button></form>
        </div>
    </aside>
    <div class="workspace">
        <header class="topbar"><span>Workspace <span class="breadcrumb">/ {{ $title }}</span></span><span class="operator">{{ auth()->user()?->name ?? 'Operator' }} <span class="avatar" aria-hidden="true">{{ mb_substr(auth()->user()?->name ?? 'O', 0, 1) }}</span></span></header>
        <main id="main">
            @if(session('status'))<div class="notice" role="status">{{ session('status') }}</div>@endif
            @if($errors->any())<div class="notice error" role="alert"><strong>Periksa kembali input.</strong><ul>@foreach($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul></div>@endif
            {{ $slot }}
        </main>
    </div>
    @livewireScripts
</body>
</html>
