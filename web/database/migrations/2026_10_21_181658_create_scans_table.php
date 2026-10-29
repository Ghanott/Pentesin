<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('scans', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('kind')->default('scan');
            $table->text('target')->nullable();
            $table->text('instruction')->nullable();
            $table->string('mode')->default('standard');
            $table->boolean('context_mode')->default(false);
            $table->string('status')->default('queued')->index();
            $table->string('phase')->nullable();
            $table->text('error')->nullable();
            $table->foreignId('llm_profile_id')->nullable()->constrained('llm_profiles')->nullOnDelete();
            $table->text('llm_snapshot');
            $table->json('findings')->nullable();
            $table->json('artifacts')->nullable();
            $table->json('test_result')->nullable();
            $table->decimal('max_budget', 10, 2)->nullable();
            $table->string('lease_token', 64)->nullable();
            $table->timestamp('lease_expires_at')->nullable();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->timestamps();
        });
        Schema::create('runner_states', function (Blueprint $table) {
            $table->unsignedInteger('id')->primary();
        });
        DB::table('runner_states')->insert(['id' => 1]);
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_artifacts');
        Schema::dropIfExists('runner_states');
        Schema::dropIfExists('scans');
    }
};
