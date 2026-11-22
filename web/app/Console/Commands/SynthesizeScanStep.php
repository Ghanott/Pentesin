<?php

namespace App\Console\Commands;

use App\Http\Controllers\DashboardController;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;

#[Signature('scans:synthesize-step {scanId} {findingId} {language} {--profile-id=}')]
#[Description('Run a single finding/language AI report synthesis step in the background')]
class SynthesizeScanStep extends Command
{
    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $rawProfileId = $this->option('profile-id');
        $profileId = ($rawProfileId !== null && $rawProfileId !== '') ? (int) $rawProfileId : null;

        app(DashboardController::class)->runAsyncSynthesisStep(
            (string) $this->argument('scanId'),
            (string) $this->argument('findingId'),
            (string) $this->argument('language'),
            $profileId,
        );

        return self::SUCCESS;
    }
}
