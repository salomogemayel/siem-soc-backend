<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ProcessedLoginAlert extends Model
{
    protected $fillable = [
        'wazuh_alert_id',
        'wazuh_rule_id',
        'cis_user_id',
        'ip_address',
        'processed_at',
    ];

    protected $casts = [
        'processed_at' => 'datetime',
    ];
}
