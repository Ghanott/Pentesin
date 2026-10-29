<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasColumn('scans', 'context_mode')) {
            Schema::table('scans', function (Blueprint $table): void {
                $table->boolean('context_mode')->default(false);
            });
        }
    }

    public function down(): void
    {
        // Preserve scan settings: fresh databases already own this column in the base migration.
    }
};
