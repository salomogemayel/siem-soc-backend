<?php

namespace App\Services;

use App\Models\UnusualIpAlert;
use App\Services\UnusualIpDetectionService;
use Illuminate\Support\Facades\Http;

class WazuhIndexerService
{
    protected $indexerUrl;
    protected $username;
    protected $password;
    protected UnusualIpDetectionService $unusualIpDetectionService;

    public function __construct(UnusualIpDetectionService $unusualIpDetectionService)
    {
        $this->indexerUrl = env('WAZUH_INDEXER_URL');
        $this->username = env('WAZUH_INDEXER_USERNAME');
        $this->password = env('WAZUH_INDEXER_PASSWORD');
        $this->unusualIpDetectionService = $unusualIpDetectionService;
    }

    public function getAlerts($page = 1, $size = 20, $level = null, $search = null, $agent = null)
    {
        try {
            $from = ($page - 1) * $size;

            $must = [];

            if ($level) {
                $range = [];

                switch (strtolower($level)) {
                    case 'high':
                        $range = ['gte' => 10];
                        break;
                    case 'medium':
                        $range = ['gte' => 5, 'lt' => 10];
                        break;
                    case 'low':
                        $range = ['lt' => 5];
                        break;
                    default:
                        if (is_numeric($level)) {
                            $range = ['gte' => (int) $level];
                        }
                        break;
                }

                if (!empty($range)) {
                    $must[] = [
                        'range' => [
                            'rule.level' => $range
                        ]
                    ];
                }
            }

            if ($search) {
                $must[] = [
                    'multi_match' => [
                        'query' => $search,
                        'fields' => [
                            'rule.id',
                            'agent.id',
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
                    'track_total_hits' => true,

                    'from' => $from,
                    'size' => $size,

                    'query' => $query,

                    'sort' => [
                        [
                            '@timestamp' => [
                                'order' => 'desc'
                            ]
                        ]
                    ],

                    'aggs' => [
                        'severity_summary' => [
                            'filters' => [
                                'filters' => [
                                    'high' => [
                                        'range' => [
                                            'rule.level' => [
                                                'gte' => 10
                                            ]
                                        ]
                                    ],
                                    'medium' => [
                                        'range' => [
                                            'rule.level' => [
                                                'gte' => 5,
                                                'lt' => 10
                                            ]
                                        ]
                                    ],
                                    'low' => [
                                        'range' => [
                                            'rule.level' => [
                                                'lt' => 5
                                            ]
                                        ]
                                    ],
                                ]
                            ]
                        ]
                    ],
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

            $summaryBuckets = $json['aggregations']['severity_summary']['buckets'] ?? [];

            $summary = [
                'total' => $total,
                'high' => $summaryBuckets['high']['doc_count'] ?? 0,
                'medium' => $summaryBuckets['medium']['doc_count'] ?? 0,
                'low' => $summaryBuckets['low']['doc_count'] ?? 0,
            ];

            $alerts = collect($hits)->map(function ($hit) {
                $source = $hit['_source'] ?? [];

                $unusualIpResult = null;

                if ((string) data_get($source, 'rule.id') === '100320') {
                    $loginAlert = $source;
                    $loginAlert['id'] = $hit['_id'] ?? null;
                    $loginAlert['timestamp'] = data_get($source, '@timestamp');

                    $unusualIpResult = $this->unusualIpDetectionService->processLoginAlert($loginAlert);
                }

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
                    'unusual_ip_result' => $unusualIpResult,
                    'full_log' => $source,
                ];
            });

            $socAlerts = $this->getSocGeneratedAlerts($level, $search, $agent);

            $mergedAlerts = $alerts
                ->merge($socAlerts)
                ->sortByDesc('timestamp')
                ->values();

            $summary['total'] += $socAlerts->count();
            $summary['high'] += $socAlerts->where('level', '>=', 10)->count();

            return [
                'success' => true,
                'data' => $mergedAlerts,
                'total' => $total + $socAlerts->count(),
                'summary' => $summary,
                'page' => (int) $page,
                'size' => (int) $size,
                'total_pages' => ceil(($total + $socAlerts->count()) / $size)
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    private function getSocGeneratedAlerts($level = null, $search = null, $agent = null)
    {
        if (!$this->socAlertMatchesLevelFilter($level)) {
            return collect();
        }

        if ($agent && !str_contains(strtolower('SOC Analysis'), strtolower($agent)) && !str_contains(strtolower('SOC'), strtolower($agent))) {
            return collect();
        }

        $query = UnusualIpAlert::query()
            ->orderByDesc('detected_at')
            ->orderByDesc('created_at')
            ->limit(20);

        if ($search) {
            $query->where(function ($q) use ($search) {
                $q->where('cis_user_id', 'like', "%{$search}%")
                    ->orWhere('ip_address', 'like', "%{$search}%")
                    ->orWhere('wazuh_alert_id', 'like', "%{$search}%")
                    ->orWhere('wazuh_rule_id', 'like', "%{$search}%")
                    ->orWhere('reason', 'like', "%{$search}%")
                    ->orWhere('status', 'like', "%{$search}%");
            });
        }

        return $query->get()->map(function ($alert) {
            $timestamp = $alert->detected_at ?? $alert->created_at;

            return [
                'id' => 'soc-unusual-ip-' . $alert->id,
                'timestamp' => $timestamp ? $timestamp->toIso8601String() : null,
                'agent_id' => 'SOC',
                'agent_name' => 'SOC Analysis',
                'description' => "Unusual IP detected: CIS user {$alert->cis_user_id} logged in from new IP {$alert->ip_address}",
                'level' => 10,
                'rule_id' => 'SOC-UNUSUAL-IP',
                'groups' => [
                    'soc_analysis',
                    'unusual_ip',
                    'authentication',
                    'login_success',
                ],
                'mitre_id' => ['T1078'],
                'tactic' => ['Initial Access'],
                'technique' => ['Valid Accounts'],
                'alert_source' => 'soc',
                'soc_alert_type' => 'unusual_ip',
                'status' => $alert->status,
                'full_log' => [
                    'soc_alert' => $alert->toArray(),
                    'source_wazuh_alert_id' => $alert->wazuh_alert_id,
                    'source_wazuh_rule_id' => $alert->wazuh_rule_id,
                ],
            ];
        });
    }

    private function socAlertMatchesLevelFilter($level): bool
    {
        if (!$level) {
            return true;
        }

        $socLevel = 10;

        switch (strtolower($level)) {
            case 'high':
                return true;

            case 'medium':
            case 'low':
                return false;

            default:
                if (is_numeric($level)) {
                    return $socLevel >= (int) $level;
                }

                return true;
        }
    }

    public function getCriticalAlertsForNotifications($level = 10, $size = 20)
    {
        try {
            $response = Http::withBasicAuth($this->username, $this->password)
                ->withoutVerifying()
                ->post($this->indexerUrl . '/wazuh-alerts-*/_search', [
                    'size' => $size,
                    'sort' => [
                        [
                            '@timestamp' => [
                                'order' => 'desc'
                            ]
                        ]
                    ],
                    'query' => [
                        'bool' => [
                            'must' => [
                                [
                                    'range' => [
                                        'rule.level' => [
                                            'gte' => $level
                                        ]
                                    ]
                                ],
                                [
                                    'range' => [
                                        '@timestamp' => [
                                            'gte' => 'now-24h',
                                            'lte' => 'now'
                                        ]
                                    ]
                                ]
                            ]
                        ]
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
                        'full_log'
                    ]
                ]);

            if (!$response->successful()) {
                return [
                    'success' => false,
                    'error' => $response->body()
                ];
            }

            $hits = $response->json()['hits']['hits'] ?? [];

            $alerts = collect($hits)->map(function ($hit) {
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
            })->filter(function ($alert) {
                return !empty($alert['source_alert_id']);
            })->values();

            return [
                'success' => true,
                'data' => $alerts
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    public function getLogs(
        $page = 1,
        $size = 20,
        $search = '',
        $agentId = '',
        $location = '',
        $decoder = '',
        $program = '',
        $timeRange = '24h',
        $dateFrom = '',
        $dateTo = ''
    ) {
        try {
            $from = ($page - 1) * $size;

            $must = [];

            if ($timeRange === 'custom') {
                if (!empty($dateFrom) && !empty($dateTo)) {
                    $must[] = [
                        'range' => [
                            'timestamp' => [
                                'gte' => $dateFrom,
                                'lte' => $dateTo
                            ]
                        ]
                    ];
                } else {
                    $must[] = [
                        'range' => [
                            'timestamp' => [
                                'gte' => 'now-1h',
                                'lte' => 'now'
                            ]
                        ]
                    ];
                }
            } else {
                $must[] = [
                    'range' => [
                        'timestamp' => [
                            'gte' => 'now-' . $timeRange,
                            'lte' => 'now'
                        ]
                    ]
                ];
            }

            if (!empty($search)) {
                $must[] = [
                    'simple_query_string' => [
                        'query' => $search,
                        'fields' => [
                            'full_log',
                            'agent.name',
                            'agent.id',
                            'manager.name',
                            'location',
                            'decoder.name',
                            'predecoder.program_name',
                            'data.srcip',
                            'data.dstip',
                            'data.srcuser',
                            'data.dstuser',
                            'data.url',
                            'data.command'
                        ],
                        'default_operator' => 'and'
                    ]
                ];
            }

            if (!empty($agentId)) {
                $must[] = [
                    'term' => [
                        'agent.id' => $agentId
                    ]
                ];
            }

            if (!empty($location)) {
                $must[] = [
                    'match_phrase' => [
                        'location' => $location
                    ]
                ];
            }

            if (!empty($decoder)) {
                $must[] = [
                    'match_phrase' => [
                        'decoder.name' => $decoder
                    ]
                ];
            }

            if (!empty($program)) {
                $must[] = [
                    'match_phrase' => [
                        'predecoder.program_name' => $program
                    ]
                ];
            }

            $response = Http::withBasicAuth($this->username, $this->password)
                ->withoutVerifying()
                ->post($this->indexerUrl . '/wazuh-archives-*/_search', [
                    'from' => $from,
                    'size' => $size,
                    'sort' => [
                        [
                            'timestamp' => [
                                'order' => 'desc'
                            ]
                        ]
                    ],
                    'query' => [
                        'bool' => [
                            'must' => $must
                        ]
                    ],
                    'aggs' => [
                        'alert_generated' => [
                            'filter' => [
                                'exists' => [
                                    'field' => 'rule.id'
                                ]
                            ]
                        ],
                        'raw_only' => [
                            'filter' => [
                                'bool' => [
                                    'must_not' => [
                                        [
                                            'exists' => [
                                                'field' => 'rule.id'
                                            ]
                                        ]
                                    ]
                                ]
                            ]
                        ],
                        'top_sources' => [
                            'terms' => [
                                'field' => 'location',
                                'size' => 1
                            ]
                        ],
                        'top_decoders' => [
                            'terms' => [
                                'field' => 'decoder.name',
                                'size' => 1
                            ]
                        ],
                        'top_programs' => [
                            'terms' => [
                                'field' => 'predecoder.program_name',
                                'size' => 1
                            ]
                        ]
                    ],
                    '_source' => [
                        'timestamp',
                        'agent.id',
                        'agent.name',
                        'manager.name',
                        'location',
                        'full_log',
                        'decoder.name',
                        'predecoder.program_name',
                        'data.srcip',
                        'data.dstip',
                        'data.srcuser',
                        'data.dstuser',
                        'data.url',
                        'data.protocol',
                        'data.action',
                        'data.command',
                        'rule.id',
                        'rule.level',
                        'rule.description'
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

            $totalRelation = $json['hits']['total']['relation'] ?? 'eq';
            $aggs = $json['aggregations'] ?? [];

            $insights = [
                'alert_generated' => data_get($aggs, 'alert_generated.doc_count', 0),
                'raw_only' => data_get($aggs, 'raw_only.doc_count', 0),
                'top_source' => data_get($aggs, 'top_sources.buckets.0.key', '-'),
                'top_source_count' => data_get($aggs, 'top_sources.buckets.0.doc_count', 0),
                'top_decoder' => data_get($aggs, 'top_decoders.buckets.0.key', '-'),
                'top_decoder_count' => data_get($aggs, 'top_decoders.buckets.0.doc_count', 0),
                'top_program' => data_get($aggs, 'top_programs.buckets.0.key', '-'),
                'top_program_count' => data_get($aggs, 'top_programs.buckets.0.doc_count', 0),
            ];

            $logs = collect($hits)->map(function ($hit) {
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
            });

            return [
                'success' => true,
                'data' => $logs,
                'total' => $total,
                'total_relation' => $totalRelation,
                'page' => (int) $page,
                'size' => (int) $size,
                'total_pages' => ceil($total / $size),
                'insights' => $insights,
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    public function getLogFilters()
    {
        try {
            $response = Http::withBasicAuth($this->username, $this->password)
                ->withoutVerifying()
                ->post($this->indexerUrl . '/wazuh-archives-*/_search', [
                    'size' => 0,
                    'aggs' => [
                        'agents' => [
                            'terms' => [
                                'field' => 'agent.id',
                                'size' => 50
                            ],
                            'aggs' => [
                                'agent_names' => [
                                    'terms' => [
                                        'field' => 'agent.name',
                                        'size' => 1
                                    ]
                                ]
                            ]
                        ],
                        'locations' => [
                            'terms' => [
                                'field' => 'location',
                                'size' => 50
                            ]
                        ],
                        'decoders' => [
                            'terms' => [
                                'field' => 'decoder.name',
                                'size' => 50
                            ]
                        ],
                        'programs' => [
                            'terms' => [
                                'field' => 'predecoder.program_name',
                                'size' => 50
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

            $aggs = $response->json()['aggregations'] ?? [];

            $agents = collect(data_get($aggs, 'agents.buckets', []))->map(function ($bucket) {
                return [
                    'id' => $bucket['key'],
                    'name' => data_get($bucket, 'agent_names.buckets.0.key', 'Unknown Agent')
                ];
            })->values();

            $locations = collect(data_get($aggs, 'locations.buckets', []))
                ->map(fn ($bucket) => $bucket['key'])
                ->values();

            $decoders = collect(data_get($aggs, 'decoders.buckets', []))
                ->map(fn ($bucket) => $bucket['key'])
                ->values();

            $programs = collect(data_get($aggs, 'programs.buckets', []))
                ->map(fn ($bucket) => $bucket['key'])
                ->values();

            return [
                'success' => true,
                'data' => [
                    'agents' => $agents,
                    'locations' => $locations,
                    'decoders' => $decoders,
                    'programs' => $programs,
                ]
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    public function getHealthSummary()
    {
        $indexerConnected = $this->checkIndexerConnection();

        $alertsIndex = $this->getIndexMetrics('wazuh-alerts-*', '@timestamp');
        $archivesIndex = $this->getIndexMetrics('wazuh-archives-*', 'timestamp');

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

    private function checkIndexerConnection()
    {
        try {
            $response = Http::withBasicAuth($this->username, $this->password)
                ->withoutVerifying()
                ->get($this->indexerUrl);

            return $response->successful();
        } catch (\Exception $e) {
            return false;
        }
    }

    private function getIndexMetrics($indexPattern, $timeField)
    {
        try {
            $countResponse = Http::withBasicAuth($this->username, $this->password)
                ->withoutVerifying()
                ->post($this->indexerUrl . '/' . $indexPattern . '/_count', [
                    'query' => [
                        'range' => [
                            $timeField => [
                                'gte' => 'now-24h',
                                'lte' => 'now'
                            ]
                        ]
                    ]
                ]);

            $latestResponse = Http::withBasicAuth($this->username, $this->password)
                ->withoutVerifying()
                ->post($this->indexerUrl . '/' . $indexPattern . '/_search', [
                    'size' => 1,
                    'sort' => [
                        [
                            $timeField => [
                                'order' => 'desc'
                            ]
                        ]
                    ],
                    '_source' => [
                        $timeField,
                        'agent.id',
                        'agent.name',
                        'rule.id',
                        'rule.level',
                        'rule.description',
                        'full_log'
                    ]
                ]);

            if (!$countResponse->successful() || !$latestResponse->successful()) {
                return [
                    'available' => false,
                    'count_24h' => 0,
                    'latest_at' => null,
                    'latest_document' => null,
                ];
            }

            $latestHit = $latestResponse->json()['hits']['hits'][0]['_source'] ?? null;

            return [
                'available' => true,
                'count_24h' => $countResponse->json()['count'] ?? 0,
                'latest_at' => $latestHit[$timeField] ?? null,
                'latest_document' => $latestHit,
            ];

        } catch (\Exception $e) {
            return [
                'available' => false,
                'count_24h' => 0,
                'latest_at' => null,
                'latest_document' => null,
            ];
        }
    }

    public function getAgentInsightMap($agentIds = [])
    {
        $insights = [];

        foreach ($agentIds as $id) {
            $insights[$id] = [
                'alerts_24h' => 0,
                'high_alerts_24h' => 0,
                'latest_alert_at' => null,
                'latest_log_at' => null,
                'latest_data_at' => null,
                'risk_level' => 'Low',
            ];
        }

        try {
            // Alerts aggregation
            $alertsResponse = Http::withBasicAuth($this->username, $this->password)
                ->withoutVerifying()
                ->post($this->indexerUrl . '/wazuh-alerts-*/_search', [
                    'size' => 0,
                    'query' => [
                        'bool' => [
                            'must' => [
                                [
                                    'range' => [
                                        '@timestamp' => [
                                            'gte' => 'now-24h',
                                            'lte' => 'now'
                                        ]
                                    ]
                                ],
                                [
                                    'terms' => [
                                        'agent.id' => $agentIds
                                    ]
                                ]
                            ]
                        ]
                    ],
                    'aggs' => [
                        'agents' => [
                            'terms' => [
                                'field' => 'agent.id',
                                'size' => 100
                            ],
                            'aggs' => [
                                'high_alerts' => [
                                    'filter' => [
                                        'range' => [
                                            'rule.level' => [
                                                'gte' => 10
                                            ]
                                        ]
                                    ]
                                ],
                                'latest_alert' => [
                                    'max' => [
                                        'field' => '@timestamp'
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]);

            if ($alertsResponse->successful()) {
                $buckets = data_get($alertsResponse->json(), 'aggregations.agents.buckets', []);

                foreach ($buckets as $bucket) {
                    $id = $bucket['key'];

                    $insights[$id]['alerts_24h'] = $bucket['doc_count'] ?? 0;
                    $insights[$id]['high_alerts_24h'] = data_get($bucket, 'high_alerts.doc_count', 0);
                    $insights[$id]['latest_alert_at'] = data_get($bucket, 'latest_alert.value_as_string');
                }
            }

            // Logs aggregation
            $logsResponse = Http::withBasicAuth($this->username, $this->password)
                ->withoutVerifying()
                ->post($this->indexerUrl . '/wazuh-archives-*/_search', [
                    'size' => 0,
                    'query' => [
                        'bool' => [
                            'must' => [
                                [
                                    'range' => [
                                        'timestamp' => [
                                            'gte' => 'now-24h',
                                            'lte' => 'now'
                                        ]
                                    ]
                                ],
                                [
                                    'terms' => [
                                        'agent.id' => $agentIds
                                    ]
                                ]
                            ]
                        ]
                    ],
                    'aggs' => [
                        'agents' => [
                            'terms' => [
                                'field' => 'agent.id',
                                'size' => 100
                            ],
                            'aggs' => [
                                'latest_log' => [
                                    'max' => [
                                        'field' => 'timestamp'
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]);

            if ($logsResponse->successful()) {
                $buckets = data_get($logsResponse->json(), 'aggregations.agents.buckets', []);

                foreach ($buckets as $bucket) {
                    $id = $bucket['key'];

                    $insights[$id]['latest_log_at'] = data_get($bucket, 'latest_log.value_as_string');
                }
            }

            foreach ($insights as $id => $item) {
                $latestAlert = !empty($item['latest_alert_at']) ? strtotime($item['latest_alert_at']) : 0;
                $latestLog = !empty($item['latest_log_at']) ? strtotime($item['latest_log_at']) : 0;

                if ($latestAlert >= $latestLog && $latestAlert !== 0) {
                    $insights[$id]['latest_data_at'] = $item['latest_alert_at'];
                } elseif ($latestLog !== 0) {
                    $insights[$id]['latest_data_at'] = $item['latest_log_at'];
                }

                if ($item['high_alerts_24h'] > 0) {
                    $insights[$id]['risk_level'] = 'High';
                } elseif ($item['alerts_24h'] >= 10) {
                    $insights[$id]['risk_level'] = 'Medium';
                } else {
                    $insights[$id]['risk_level'] = 'Low';
                }
            }

            return $insights;

        } catch (\Exception $e) {
            return $insights;
        }
    }
}
