<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class WazuhAlertResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        $level = (int) data_get($this->resource, 'level', 0);

        return [
            'id' => data_get($this->resource, 'id'),
            'timestamp' => data_get($this->resource, 'timestamp'),

            'agent_id' => data_get($this->resource, 'agent_id', '-'),
            'agent_name' => data_get($this->resource, 'agent_name', '-'),

            'description' => data_get($this->resource, 'description', '-'),
            'level' => $level,
            'severity' => $this->getSeverity($level),

            'rule_id' => data_get($this->resource, 'rule_id', '-'),
            'groups' => data_get($this->resource, 'groups', []),

            'mitre' => [
                'id' => data_get($this->resource, 'mitre_id', []),
                'tactic' => data_get($this->resource, 'tactic', []),
                'technique' => data_get($this->resource, 'technique', []),
            ],

            'unusual_ip_result' => data_get($this->resource, 'unusual_ip_result'),
            'alert_source' => data_get($this->resource, 'alert_source', 'wazuh'),
            'soc_alert_type' => data_get($this->resource, 'soc_alert_type'),
            'status' => data_get($this->resource, 'status'),

            'correlation_role' => data_get($this->resource, 'correlation_role', 'standalone'),
            'correlation_parent_rule_id' => data_get($this->resource, 'correlation_parent_rule_id'),
            'child_count' => data_get($this->resource, 'child_count', 0),
            'child_alerts' => data_get($this->resource, 'child_alerts', []),

            'full_log' => data_get($this->resource, 'full_log', '-'),

            'srcip' => data_get($this->resource, 'srcip', '-'),
            'url' => data_get($this->resource, 'url', '-'),
            'location' => data_get($this->resource, 'location', '-'),
            'decoder' => data_get($this->resource, 'decoder', '-'),
            'manager_name' => data_get($this->resource, 'manager_name', '-'),
            'program_name' => data_get($this->resource, 'program_name', '-'),
        ];
    }

    private function getSeverity(int $level): string
    {
        if ($level >= 10) {
            return 'high';
        }

        if ($level >= 5) {
            return 'medium';
        }

        return 'low';
    }
}
