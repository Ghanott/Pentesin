<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ScanEvent extends Model
{
    protected $guarded = ['id'];

    protected function casts(): array
    {
        return ['data' => 'array'];
    }

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }
}
