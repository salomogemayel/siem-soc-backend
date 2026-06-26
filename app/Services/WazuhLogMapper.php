<?php

namespace App\Services;

use Illuminate\Support\Collection;

class WazuhLogMapper
{
    public function mapMany(array $hits): Collection
    {
        return collect($hits)->map(function ($hit) {
            return $this->map($hit);
        });
    }

    private function map(array $hit): array
    {
        $source = $hit['_source'] ?? [];

        return [
            'id' => $hit['_id'] ?? null,
            'timestamp' => data_get($source, 'timestamp', '-'),
            'agent_id' => data_get($source, 'agent.id', '-'),
            'agent_name' => data_get($source, 'agent.name', '-'),
            'manager_name' => data_get($source, 'manager.name', '-'),
            'location' => data_get($source, 'location', '-'),
            'decoder' => data_get($source, 'decoder.name', '-'),
            'program_name' => data_get($source, 'predecoder.program_name', '-'),
            'srcip' => data_get($source, 'data.srcip', '-'),
            'dstip' => data_get($source, 'data.dstip', '-'),
            'srcuser' => data_get($source, 'data.srcuser', '-'),
            'dstuser' => data_get($source, 'data.dstuser', '-'),
            'url' => data_get($source, 'data.url', '-'),
            'protocol' => data_get($source, 'data.protocol', '-'),
            'action' => data_get($source, 'data.action', '-'),
            'command' => data_get($source, 'data.command', '-'),
            'rule_id' => data_get($source, 'rule.id', null),
            'rule_level' => data_get($source, 'rule.level', null),
            'rule_description' => data_get($source, 'rule.description', null),
            'full_log' => data_get($source, 'full_log', '-'),
            'raw' => $source,
        ];
    }
}
