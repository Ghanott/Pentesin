<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ScanCommand extends Model
{
    use HasUuids;

    protected $guarded = ['id'];

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }
}
