<?php

namespace App\Services;

class WazuhLogFilterService
{
    public function __construct(
        private WazuhIndexerClient $indexerClient
    ) {
    }

    public function getFilters(): array
    {
        try {
            $response = $this->indexerClient->post(
                '/' . config('wazuh.indexes.archives') . '/_search',
                $this->buildPayload()
            );

            if (!$response->successful()) {
                return [
                    'success' => false,
                    'error' => $response->body(),
                ];
            }

            $aggs = $response->json()['aggregations'] ?? [];

            return [
                'success' => true,
                'data' => [
                    'agents' => $this->mapAgents($aggs),
                    'locations' => $this->mapBuckets($aggs, 'locations'),
                    'decoders' => $this->mapBuckets($aggs, 'decoders'),
                    'programs' => $this->mapBuckets($aggs, 'programs'),
                ],
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    private function buildPayload(): array
    {
        return [
            'size' => 0,
            'aggs' => [
                'agents' => [
                    'terms' => [
                        'field' => 'agent.id',
                        'size' => 50,
                    ],
                    'aggs' => [
                        'agent_names' => [
                            'terms' => [
                                'field' => 'agent.name',
                                'size' => 1,
                            ],
                        ],
                    ],
                ],
                'locations' => [
                    'terms' => [
                        'field' => 'location',
                        'size' => 50,
                    ],
                ],
                'decoders' => [
                    'terms' => [
                        'field' => 'decoder.name',
                        'size' => 50,
                    ],
                ],
                'programs' => [
                    'terms' => [
                        'field' => 'predecoder.program_name',
                        'size' => 50,
                    ],
                ],
            ],
        ];
    }

    private function mapAgents(array $aggs)
    {
        return collect(data_get($aggs, 'agents.buckets', []))
            ->map(function ($bucket) {
                return [
                    'id' => $bucket['key'],
                    'name' => data_get($bucket, 'agent_names.buckets.0.key', 'Unknown Agent'),
                ];
            })
            ->values();
    }

    private function mapBuckets(array $aggs, string $key)
    {
        return collect(data_get($aggs, "{$key}.buckets", []))
            ->map(fn ($bucket) => $bucket['key'])
            ->values();
    }
}
