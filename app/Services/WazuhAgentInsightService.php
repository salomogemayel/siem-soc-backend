<?php

namespace App\Services;

class WazuhAgentInsightService
{
    public function __construct(
        private WazuhIndexerClient $indexerClient
    ) {
    }

    public function getInsightMap(array $agentIds = []): array
    {
        $insights = $this->makeEmptyInsights($agentIds);

        if (empty($agentIds)) {
            return $insights;
        }

        try {
            $this->fillAlertInsights($insights, $agentIds);
            $this->fillLogInsights($insights, $agentIds);

            return $this->calculateRiskLevels($insights);

        } catch (\Exception $e) {
            return $insights;
        }
    }

    private function makeEmptyInsights(array $agentIds): array
    {
        $insights = [];

        foreach ($agentIds as $agentId) {
            $insights[$agentId] = [
                'alerts_24h' => 0,
                'high_alerts_24h' => 0,
                'latest_alert_at' => null,
                'latest_log_at' => null,
                'latest_data_at' => null,
                'risk_level' => 'Low',
            ];
        }

        return $insights;
    }

    private function fillAlertInsights(array &$insights, array $agentIds): void
    {
        $response = $this->indexerClient->post(
            '/' . config('wazuh.indexes.alerts') . '/_search',
            $this->buildAlertPayload($agentIds)
        );

        if (!$response->successful()) {
            return;
        }

        $buckets = data_get($response->json(), 'aggregations.agents.buckets', []);

        foreach ($buckets as $bucket) {
            $agentId = $bucket['key'];

            if (!isset($insights[$agentId])) {
                continue;
            }

            $insights[$agentId]['alerts_24h'] = $bucket['doc_count'] ?? 0;
            $insights[$agentId]['high_alerts_24h'] = data_get($bucket, 'high_alerts.doc_count', 0);
            $insights[$agentId]['latest_alert_at'] = data_get($bucket, 'latest_alert.value_as_string');
        }
    }

    private function fillLogInsights(array &$insights, array $agentIds): void
    {
        $response = $this->indexerClient->post(
            '/' . config('wazuh.indexes.archives') . '/_search',
            $this->buildLogPayload($agentIds)
        );

        if (!$response->successful()) {
            return;
        }

        $buckets = data_get($response->json(), 'aggregations.agents.buckets', []);

        foreach ($buckets as $bucket) {
            $agentId = $bucket['key'];

            if (!isset($insights[$agentId])) {
                continue;
            }

            $insights[$agentId]['latest_log_at'] = data_get($bucket, 'latest_log.value_as_string');
        }
    }

    private function calculateRiskLevels(array $insights): array
    {
        foreach ($insights as $agentId => $insight) {
            $latestAlert = $insight['latest_alert_at'] ? strtotime($insight['latest_alert_at']) : 0;
            $latestLog = $insight['latest_log_at'] ? strtotime($insight['latest_log_at']) : 0;

            if ($latestAlert >= $latestLog && $latestAlert !== 0) {
                $insights[$agentId]['latest_data_at'] = $insight['latest_alert_at'];
            } elseif ($latestLog !== 0) {
                $insights[$agentId]['latest_data_at'] = $insight['latest_log_at'];
            }

            if ($insight['high_alerts_24h'] > 0) {
                $insights[$agentId]['risk_level'] = 'High';
            } elseif ($insight['alerts_24h'] >= 10) {
                $insights[$agentId]['risk_level'] = 'Medium';
            } else {
                $insights[$agentId]['risk_level'] = 'Low';
            }
        }

        return $insights;
    }

    private function buildAlertPayload(array $agentIds): array
    {
        return [
            'size' => 0,
            'query' => [
                'bool' => [
                    'must' => [
                        [
                            'range' => [
                                '@timestamp' => [
                                    'gte' => 'now-24h',
                                    'lte' => 'now',
                                ],
                            ],
                        ],
                        [
                            'terms' => [
                                'agent.id' => $agentIds,
                            ],
                        ],
                    ],
                ],
            ],
            'aggs' => [
                'agents' => [
                    'terms' => [
                        'field' => 'agent.id',
                        'size' => 100,
                    ],
                    'aggs' => [
                        'high_alerts' => [
                            'filter' => [
                                'range' => [
                                    'rule.level' => [
                                        'gte' => 10,
                                    ],
                                ],
                            ],
                        ],
                        'latest_alert' => [
                            'max' => [
                                'field' => '@timestamp',
                            ],
                        ],
                    ],
                ],
            ],
        ];
    }

    private function buildLogPayload(array $agentIds): array
    {
        return [
            'size' => 0,
            'query' => [
                'bool' => [
                    'must' => [
                        [
                            'range' => [
                                'timestamp' => [
                                    'gte' => 'now-24h',
                                    'lte' => 'now',
                                ],
                            ],
                        ],
                        [
                            'terms' => [
                                'agent.id' => $agentIds,
                            ],
                        ],
                    ],
                ],
            ],
            'aggs' => [
                'agents' => [
                    'terms' => [
                        'field' => 'agent.id',
                        'size' => 100,
                    ],
                    'aggs' => [
                        'latest_log' => [
                            'max' => [
                                'field' => 'timestamp',
                            ],
                        ],
                    ],
                ],
            ],
        ];
    }
}
