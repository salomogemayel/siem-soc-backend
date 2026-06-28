<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class UserIpBaseline extends Model
{
    protected $fillable = [
        'cis_user_id',
        'ip_address',
        'first_seen_at',
        'last_seen_at',
        'login_count',
        'is_trusted',
        'device'
    ];

    protected $casts = [
        'first_seen_at' => 'datetime',
        'last_seen_at' => 'datetime',
        'is_trusted' => 'boolean',
        'login_count' => 'integer',
    ];
}
