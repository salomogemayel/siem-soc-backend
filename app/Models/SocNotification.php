<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class SocNotification extends Model
{
    protected $fillable = [
        'user_id',
        'source_alert_id',
        'type',
        'title',
        'message',
        'severity',
        'rule_id',
        'rule_level',
        'agent_id',
        'agent_name',
        'alert_timestamp',
        'is_read',
        'read_at',
        'metadata',
    ];

    protected $casts = [
        'is_read' => 'boolean',
        'metadata' => 'array',
        'read_at' => 'datetime',
    ];
}
