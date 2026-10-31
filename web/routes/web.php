<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use Illuminate\Support\Facades\Route;

Route::middleware('guest')->group(function (): void {
    Route::get('/login', [AuthController::class, 'show'])->name('login');
    Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:10,1')->name('login.submit');
});

Route::middleware('auth')->group(function (): void {
    Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
    Route::get('/', [DashboardController::class, 'index'])->name('dashboard');
    Route::get('/history', [DashboardController::class, 'history'])->name('scans.history');
    Route::get('/settings', [DashboardController::class, 'settings'])->name('settings');
    Route::post('/profiles', [DashboardController::class, 'storeProfile'])->name('profiles.store');
    Route::put('/profiles/{profile}', [DashboardController::class, 'updateProfile'])->name('profiles.update');
    Route::delete('/profiles/{profile}', [DashboardController::class, 'destroyProfile'])->name('profiles.destroy');
    Route::post('/profiles/{profile}/test', [DashboardController::class, 'testProfile'])->middleware('throttle:10,1')->name('profiles.test');
    Route::get('/profiles/{profile}/tests/{scan}', [DashboardController::class, 'profileTestResult'])->name('profiles.test-result');
    Route::post('/scans', [DashboardController::class, 'store'])->middleware('throttle:5,1')->name('scans.store');
    Route::get('/scans/{scan}', [DashboardController::class, 'show'])->name('scans.show');
    Route::get('/scans/{scan}/report', [DashboardController::class, 'report'])->name('scans.report');
    Route::post('/scans/{scan}/report/synthesize', [DashboardController::class, 'synthesizeReport'])->name('scans.report.synthesize');
    Route::get('/scans/{scan}/feed', [DashboardController::class, 'feed'])->name('scans.feed');
    Route::post('/scans/{scan}/messages', [DashboardController::class, 'message'])->middleware('throttle:30,1')->name('scans.messages');
    Route::post('/scans/{scan}/stop', [DashboardController::class, 'stop'])->name('scans.stop');
    Route::delete('/scans/{scan}', [DashboardController::class, 'destroy'])->name('scans.destroy');
    Route::get('/scans/{scan}/artifacts/{name}', [DashboardController::class, 'artifact'])->name('scans.artifacts');
});
