<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use RuntimeException;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        if (app()->environment('production')) {
            $token = (string) config('pentesin.runner_token');
            if (strlen($token) < 48 || str_contains($token, 'generate-a-long-random-token')) {
                throw new RuntimeException('PENTESIN_RUNNER_TOKEN must be a unique random secret of at least 48 characters in production.');
            }
        }
    }
}
