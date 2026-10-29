<?php

use App\Http\Controllers\DashboardController;
use App\Http\Controllers\Internal\RunnerController;
use Illuminate\Support\Facades\Route;

Route::prefix('internal/runner/v1')->middleware('runner.auth')->group(function (): void {
    Route::post('/claim', [RunnerController::class, 'claim'])->name('runner.claim');
    Route::post('/scans/{scan}/heartbeat', [RunnerController::class, 'heartbeat'])->name('runner.heartbeat');
    Route::post('/scans/{scan}/artifacts/{name}', [DashboardController::class, 'storeArtifact'])->name('runner.artifact');
    Route::post('/scans/{scan}/commands/{command}/ack', [RunnerController::class, 'acknowledge'])->name('runner.ack');
});
