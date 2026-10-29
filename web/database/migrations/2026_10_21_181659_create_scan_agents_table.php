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
        Schema::create('scan_agents', function (Blueprint $table) {
            $table->id();
            $table->foreignUuid('scan_id')->constrained()->cascadeOnDelete();
            $table->string('agent_id', 200);
            $table->string('parent_id', 200)->nullable();
            $table->string('name', 500);
            $table->string('status');
            $table->timestamps();
            $table->unique(['scan_id', 'agent_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_agents');
    }
};
