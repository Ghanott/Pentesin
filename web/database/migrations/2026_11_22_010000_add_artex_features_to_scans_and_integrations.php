<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasColumn('scans', 'noise_profile')) {
            Schema::table('scans', function (Blueprint $table): void {
                $table->string('noise_profile', 32)->default('off');
            });
        }
        if (! Schema::hasColumn('scans', 'auth_credentials')) {
            Schema::table('scans', function (Blueprint $table): void {
                $table->text('auth_credentials')->nullable();
            });
        }
        if (! Schema::hasColumn('scans', 'integration_snapshot')) {
            Schema::table('scans', function (Blueprint $table): void {
                $table->text('integration_snapshot')->nullable();
            });
        }
        if (! Schema::hasColumn('scans', 'retest_target_finding')) {
            Schema::table('scans', function (Blueprint $table): void {
                $table->json('retest_target_finding')->nullable();
            });
        }

        if (! Schema::hasTable('integration_settings')) {
            Schema::create('integration_settings', function (Blueprint $table): void {
                $table->id();
                $table->foreignId('user_id')->unique()->constrained()->cascadeOnDelete();
                $table->string('web_search_provider', 32)->default('auto');
                $table->text('exa_api_key')->nullable();
                $table->text('perplexity_api_key')->nullable();
                $table->text('tavily_api_key')->nullable();
                $table->text('brave_api_key')->nullable();
                $table->timestamps();
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('integration_settings');
        foreach (['noise_profile', 'auth_credentials', 'integration_snapshot', 'retest_target_finding'] as $col) {
            if (Schema::hasColumn('scans', $col)) {
                Schema::table('scans', function (Blueprint $table) use ($col): void {
                    $table->dropColumn($col);
                });
            }
        }
    }
};
