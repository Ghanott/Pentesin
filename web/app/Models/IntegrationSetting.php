<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class IntegrationSetting extends Model
{
    protected $guarded = ['id'];

    protected $hidden = [
        'exa_api_key',
        'perplexity_api_key',
        'tavily_api_key',
        'brave_api_key',
    ];

    protected function casts(): array
    {
        return [
            'exa_api_key' => 'encrypted',
            'perplexity_api_key' => 'encrypted',
            'tavily_api_key' => 'encrypted',
            'brave_api_key' => 'encrypted',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * @return array<string, string|null>
     */
    public function runnerPayload(): array
    {
        return [
            'web_search_provider' => $this->web_search_provider ?: 'auto',
            'exa_api_key' => $this->exa_api_key,
            'perplexity_api_key' => $this->perplexity_api_key,
            'tavily_api_key' => $this->tavily_api_key,
            'brave_api_key' => $this->brave_api_key,
        ];
    }
}
