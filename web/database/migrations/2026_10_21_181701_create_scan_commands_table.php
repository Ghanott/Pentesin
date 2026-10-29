<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('scan_commands', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('scan_id')->constrained()->cascadeOnDelete();
            $table->string('type');
            $table->string('agent_id', 200)->nullable();
            $table->text('message')->nullable();
            $table->string('status')->default('queued');
            $table->text('error')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_commands');
    }
};
