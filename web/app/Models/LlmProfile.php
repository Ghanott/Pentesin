<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class LlmProfile extends Model
{
    use HasFactory;

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    protected $guarded = ['id'];

    protected $hidden = ['api_key'];

    protected function casts(): array
    {
        return ['api_key' => 'encrypted'];
    }

    public function runnerProfile(): array
    {
        $model = $this->model;
        if (! str_contains($model, '/')) {
            $model = 'openai/'.$model;
        }

        return ['model' => $model, 'api_base' => $this->api_base, 'api_type' => 'chat_completions', 'api_key' => $this->api_key];
    }
}
