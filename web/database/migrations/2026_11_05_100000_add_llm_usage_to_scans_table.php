<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('scans', function (Blueprint $table): void {
            if (! Schema::hasColumn('scans', 'llm_usage')) {
                $table->json('llm_usage')->nullable();
            }
            if (! Schema::hasColumn('scans', 'total_tokens')) {
                $table->unsignedBigInteger('total_tokens')->default(0);
            }
        });
    }

    public function down(): void
    {
        Schema::table('scans', function (Blueprint $table): void {
            if (Schema::hasColumn('scans', 'total_tokens')) {
                $table->dropColumn('total_tokens');
            }
            if (Schema::hasColumn('scans', 'llm_usage')) {
                $table->dropColumn('llm_usage');
            }
        });
    }
};
