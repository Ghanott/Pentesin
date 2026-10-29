<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Scan extends Model
{
    use HasFactory, HasUuids;

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    protected $guarded = ['id'];

    protected $hidden = ['llm_snapshot', 'lease_token'];

    protected function casts(): array
    {
        return ['llm_snapshot' => 'encrypted:array', 'context_mode' => 'boolean', 'findings' => 'array', 'artifacts' => 'array', 'test_result' => 'array', 'lease_expires_at' => 'datetime', 'started_at' => 'datetime', 'finished_at' => 'datetime', 'max_budget' => 'float'];
    }

    public function agents(): HasMany
    {
        return $this->hasMany(ScanAgent::class);
    }

    public function events(): HasMany
    {
        return $this->hasMany(ScanEvent::class);
    }

    public function commands(): HasMany
    {
        return $this->hasMany(ScanCommand::class);
    }

    public function active(): bool
    {
        return in_array($this->status, ['queued', 'running'], true);
    }

    public function llmProfile(): BelongsTo
    {
        return $this->belongsTo(LlmProfile::class);
    }
}
