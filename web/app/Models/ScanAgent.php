<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ScanAgent extends Model
{
    protected $guarded = ['id'];

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }
}
