<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasColumn('scans', 'smart_recon')) {
            Schema::table('scans', function (Blueprint $table): void {
                $table->boolean('smart_recon')->default(false);
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasColumn('scans', 'smart_recon')) {
            Schema::table('scans', function (Blueprint $table): void {
                $table->dropColumn('smart_recon');
            });
        }
    }
};
