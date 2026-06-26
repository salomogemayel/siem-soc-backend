<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class WazuhLogResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => data_get($this->resource, 'id'),
            'timestamp' => data_get($this->resource, 'timestamp', '-'),

            'agent_id' => data_get($this->resource, 'agent_id', '-'),
            'agent_name' => data_get($this->resource, 'agent_name', '-'),
            'manager_name' => data_get($this->resource, 'manager_name', '-'),

            'location' => data_get($this->resource, 'location', '-'),
            'decoder' => data_get($this->resource, 'decoder', '-'),
            'program_name' => data_get($this->resource, 'program_name', '-'),

            'srcip' => data_get($this->resource, 'srcip', '-'),
            'dstip' => data_get($this->resource, 'dstip', '-'),
            'srcuser' => data_get($this->resource, 'srcuser', '-'),
            'dstuser' => data_get($this->resource, 'dstuser', '-'),

            'url' => data_get($this->resource, 'url', '-'),
            'protocol' => data_get($this->resource, 'protocol', '-'),
            'action' => data_get($this->resource, 'action', '-'),
            'command' => data_get($this->resource, 'command', '-'),

            'rule_id' => data_get($this->resource, 'rule_id'),
            'rule_level' => data_get($this->resource, 'rule_level'),
            'rule_description' => data_get($this->resource, 'rule_description'),

            'agent' => [
                'id' => data_get($this->resource, 'agent_id', '-'),
                'name' => data_get($this->resource, 'agent_name', '-'),
            ],

            'network' => [
                'srcip' => data_get($this->resource, 'srcip', '-'),
                'dstip' => data_get($this->resource, 'dstip', '-'),
                'protocol' => data_get($this->resource, 'protocol', '-'),
            ],

            'user' => [
                'srcuser' => data_get($this->resource, 'srcuser', '-'),
                'dstuser' => data_get($this->resource, 'dstuser', '-'),
            ],

            'request' => [
                'url' => data_get($this->resource, 'url', '-'),
                'action' => data_get($this->resource, 'action', '-'),
                'command' => data_get($this->resource, 'command', '-'),
            ],

            'rule' => [
                'id' => data_get($this->resource, 'rule_id'),
                'level' => data_get($this->resource, 'rule_level'),
                'description' => data_get($this->resource, 'rule_description'),
            ],

            'full_log' => data_get($this->resource, 'full_log', '-'),
            'raw' => data_get($this->resource, 'raw'),
        ];
    }
}
