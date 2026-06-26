<?php

namespace App\Services;

use Illuminate\Support\Collection;

class WazuhAlertMapper
{
    public function __construct(
        private UnusualIpDetectionService $unusualIpDetectionService
    ) {
    }

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
            'timestamp' => data_get($source, '@timestamp'),
            'agent_id' => data_get($source, 'agent.id', '-'),
            'agent_name' => data_get($source, 'agent.name', '-'),
            'description' => data_get($source, 'rule.description', '-'),
            'level' => data_get($source, 'rule.level', 0),
            'rule_id' => data_get($source, 'rule.id', '-'),
            'groups' => data_get($source, 'rule.groups', []),
            'mitre_id' => data_get($source, 'rule.mitre.id', []),
            'tactic' => data_get($source, 'rule.mitre.tactic', []),
            'technique' => data_get($source, 'rule.mitre.technique', []),
            'unusual_ip_result' => $this->detectUnusualIp($hit, $source),
            'full_log' => data_get($source, 'full_log', '-'),
            'raw' => $source,
            'srcip' => data_get($source, 'data.srcip', data_get($source, 'srcip', '-')),
            'url' => data_get($source, 'data.url', data_get($source, 'url', '-')),
            'location' => data_get($source, 'location', '-'),
            'decoder' => data_get($source, 'decoder.name', '-'),
            'manager_name' => data_get($source, 'manager.name', '-'),
            'program_name' => data_get($source, 'program_name', '-'),
        ];
    }

    private function detectUnusualIp(array $hit, array $source): mixed
    {
        if ((string) data_get($source, 'rule.id') !== '100102') {
            return null;
        }

        $loginAlert = $source;
        $loginAlert['id'] = $hit['_id'] ?? null;
        $loginAlert['timestamp'] = data_get($source, '@timestamp');

        return $this->unusualIpDetectionService->processLoginAlert($loginAlert);
    }
}
