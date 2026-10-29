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
        Schema::create('scan_events', function (Blueprint $table) {
            $table->id();
            $table->foreignUuid('scan_id')->constrained()->cascadeOnDelete();
            $table->string('source_id', 200);
            $table->string('agent_id', 200)->nullable();
            $table->string('type', 100);
            $table->json('data');
            $table->unsignedInteger('version')->default(0);
            $table->timestamps();
            $table->unique(['scan_id', 'source_id', 'version']);
            $table->index(['scan_id', 'id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_events');
    }
};
