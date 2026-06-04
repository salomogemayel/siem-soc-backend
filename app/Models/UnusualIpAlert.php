<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class UnusualIpAlert extends Model
{
    protected $fillable = [
        'cis_user_id',
        'ip_address',
        'wazuh_alert_id',
        'wazuh_rule_id',
        'detected_at',
        'reason',
        'status',
    ];

    protected $casts = [
        'detected_at' => 'datetime',
    ];
}
