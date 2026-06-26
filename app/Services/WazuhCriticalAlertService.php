<?php

namespace App\Services;

class WazuhCriticalAlertService
{
    public function __construct(
        private WazuhIndexerClient $indexerClient
    ) {
    }

    public function getForNotifications($level = 10, $size = 20): array
    {
        try {
            $response = $this->indexerClient->post(
                '/' . config('wazuh.indexes.alerts') . '/_search',
                $this->buildPayload($level, $size)
            );

            if (!$response->successful()) {
                return [
                    'success' => false,
                    'error' => $response->body(),
                ];
            }

            $hits = $response->json()['hits']['hits'] ?? [];

            return [
                'success' => true,
                'data' => $this->mapAlerts($hits),
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    private function buildPayload($level, $size): array
    {
        return [
            'size' => (int) $size,
            'sort' => [
                [
                    '@timestamp' => [
                        'order' => 'desc',
                    ],
                ],
            ],
            'query' => [
                'bool' => [
                    'must' => [
                        [
                            'range' => [
                                'rule.level' => [
                                    'gte' => (int) $level,
                                ],
                            ],
                        ],
                        [
                            'range' => [
                                '@timestamp' => [
                                    'gte' => 'now-24h',
                                    'lte' => 'now',
                                ],
                            ],
                        ],
                    ],
                ],
            ],
            '_source' => [
                '@timestamp',
                'agent.id',
                'agent.name',
                'rule.id',
                'rule.level',
                'rule.description',
                'rule.groups',
                'rule.mitre.id',
                'rule.mitre.tactic',
                'rule.mitre.technique',
                'full_log',
            ],
        ];
    }

    private function mapAlerts(array $hits)
    {
        return collect($hits)
            ->map(function ($hit) {
                $source = $hit['_source'] ?? [];

                return [
                    'source_alert_id' => $hit['_id'] ?? null,
                    'timestamp' => data_get($source, '@timestamp'),
                    'agent_id' => data_get($source, 'agent.id', '-'),
                    'agent_name' => data_get($source, 'agent.name', '-'),
                    'rule_id' => data_get($source, 'rule.id', '-'),
                    'rule_level' => data_get($source, 'rule.level', 0),
                    'description' => data_get($source, 'rule.description', '-'),
                    'full_log' => data_get($source, 'full_log', '-'),
                    'raw' => $source,
                ];
            })
            ->filter(function ($alert) {
                return !empty($alert['source_alert_id']);
            })
            ->values();
    }
}
