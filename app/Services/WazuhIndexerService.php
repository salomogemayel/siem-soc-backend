<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;

class WazuhIndexerService
{
    protected $indexerUrl;
    protected $username;
    protected $password;

    public function __construct()
    {
        $this->indexerUrl = env('WAZUH_INDEXER_URL');
        $this->username = env('WAZUH_INDEXER_USERNAME');
        $this->password = env('WAZUH_INDEXER_PASSWORD');
    }

    public function getAlerts($page = 1, $size = 20, $level = null, $search = null, $agent = null)
    {
        try {
            $from = ($page - 1) * $size;

            $must = [];

            if ($level) {
                $must[] = [
                    'range' => [
                        'rule.level' => [
                            'gte' => (int) $level
                        ]
                    ]
                ];
            }

            if ($search) {
                $must[] = [
                    'multi_match' => [
                        'query' => $search,
                        'fields' => [
                            'rule.description',
                            'agent.name',
                            'rule.groups',
                            'rule.mitre.technique',
                            'rule.mitre.tactic'
                        ]
                    ]
                ];
            }

            if ($agent) {
                $must[] = [
                    'match' => [
                        'agent.name' => $agent
                    ]
                ];
            }

            $query = empty($must)
                ? ['match_all' => (object) []]
                : ['bool' => ['must' => $must]];

            $response = Http::withBasicAuth($this->username, $this->password)
                ->withoutVerifying()
                ->post($this->indexerUrl . '/wazuh-alerts-*/_search', [
                    'from' => $from,
                    'size' => $size,
                    'query' => $query,
                    'sort' => [
                        [
                            '@timestamp' => [
                                'order' => 'desc'
                            ]
                        ]
                    ]
                ]);

            if (!$response->successful()) {
                return [
                    'success' => false,
                    'error' => $response->body()
                ];
            }

            $json = $response->json();

            $hits = $json['hits']['hits'] ?? [];
            $total = $json['hits']['total']['value'] ?? 0;

            $alerts = collect($hits)->map(function ($hit) {
                $source = $hit['_source'] ?? [];

                return [
                    'id' => $hit['_id'] ?? null,
                    'timestamp' => $source['@timestamp'] ?? null,
                    'agent_id' => $source['agent']['id'] ?? '-',
                    'agent_name' => $source['agent']['name'] ?? '-',
                    'description' => $source['rule']['description'] ?? '-',
                    'level' => $source['rule']['level'] ?? 0,
                    'rule_id' => $source['rule']['id'] ?? '-',
                    'groups' => $source['rule']['groups'] ?? [],
                    'mitre_id' => $source['rule']['mitre']['id'] ?? [],
                    'tactic' => $source['rule']['mitre']['tactic'] ?? [],
                    'technique' => $source['rule']['mitre']['technique'] ?? [],
                    'full_log' => $source,
                ];
            });

            return [
                'success' => true,
                'data' => $alerts,
                'total' => $total,
                'page' => (int) $page,
                'size' => (int) $size,
                'total_pages' => ceil($total / $size)
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
}
