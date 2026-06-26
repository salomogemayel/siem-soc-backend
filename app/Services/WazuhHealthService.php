<?php

namespace App\Services;

class WazuhHealthService
{
    public function __construct(
        private WazuhIndexerClient $indexerClient
    ) {
    }

    public function getSummary(): array
    {
        $indexerConnected = $this->checkIndexerConnection();

        $alertsIndex = $this->getIndexMetrics(
            config('wazuh.indexes.alerts'),
            '@timestamp'
        );

        $archivesIndex = $this->getIndexMetrics(
            config('wazuh.indexes.archives'),
            'timestamp'
        );

        return [
            'indexer_connected' => $indexerConnected,

            'indices' => [
                'alerts' => $alertsIndex,
                'archives' => $archivesIndex,
            ],

            'health' => [
                'indexer' => $indexerConnected ? 'connected' : 'error',
                'alerts_pipeline' => $alertsIndex['count_24h'] > 0 ? 'receiving' : 'idle',
                'logs_pipeline' => $archivesIndex['count_24h'] > 0 ? 'receiving' : 'idle',
            ],

            'metrics' => [
                'alerts_last_24h' => $alertsIndex['count_24h'],
                'logs_last_24h' => $archivesIndex['count_24h'],
            ],

            'latest' => [
                'latest_alert_at' => $alertsIndex['latest_at'],
                'latest_log_at' => $archivesIndex['latest_at'],
            ],
        ];
    }

    private function checkIndexerConnection(): bool
    {
        try {
            $response = $this->indexerClient->get();

            return $response->successful();
        } catch (\Exception $e) {
            return false;
        }
    }

    private function getIndexMetrics(string $indexPattern, string $timeField): array
    {
        try {
            $countResponse = $this->indexerClient->post(
                '/' . $indexPattern . '/_count',
                [
                    'query' => [
                        'range' => [
                            $timeField => [
                                'gte' => 'now-24h',
                                'lte' => 'now',
                            ],
                        ],
                    ],
                ]
            );

            $latestResponse = $this->indexerClient->post(
                '/' . $indexPattern . '/_search',
                [
                    'size' => 1,
                    'sort' => [
                        [
                            $timeField => [
                                'order' => 'desc',
                            ],
                        ],
                    ],
                    '_source' => [
                        $timeField,
                        'agent.id',
                        'agent.name',
                        'rule.id',
                        'rule.level',
                        'rule.description',
                        'full_log',
                    ],
                ]
            );

            if (!$countResponse->successful() || !$latestResponse->successful()) {
                return $this->emptyMetrics();
            }

            $latestHit = $latestResponse->json()['hits']['hits'][0]['_source'] ?? null;

            return [
                'available' => true,
                'count_24h' => $countResponse->json()['count'] ?? 0,
                'latest_at' => $latestHit[$timeField] ?? null,
                'latest_document' => $latestHit,
            ];

        } catch (\Exception $e) {
            return $this->emptyMetrics();
        }
    }

    private function emptyMetrics(): array
    {
        return [
            'available' => false,
            'count_24h' => 0,
            'latest_at' => null,
            'latest_document' => null,
        ];
    }
}
