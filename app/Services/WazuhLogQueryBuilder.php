<?php

namespace App\Services;

class WazuhLogQueryBuilder
{
    public function buildSearchPayload(
        int $page,
        int $size,
        string $search = '',
        string $agentId = '',
        string $location = '',
        string $decoder = '',
        string $program = '',
        string $timeRange = '24h',
        string $dateFrom = '',
        string $dateTo = '',
        string $logType = '',
        string $logScope = 'cis'
    ): array {
        return [
            'from' => ($page - 1) * $size,
            'size' => $size,
            'sort' => [
                [
                    'timestamp' => [
                        'order' => 'desc',
                    ],
                ],
            ],
            'query' => [
                'bool' => [
                    'must' => $this->buildMustFilters(
                        $search,
                        $agentId,
                        $location,
                        $decoder,
                        $program,
                        $timeRange,
                        $dateFrom,
                        $dateTo,
                        $logType,
                        $logScope
                    ),
                ],
            ],
            'aggs' => $this->buildAggregations(),
            '_source' => $this->getSourceFields(),
        ];
    }

    private function buildMustFilters(
        string $search,
        string $agentId,
        string $location,
        string $decoder,
        string $program,
        string $timeRange,
        string $dateFrom,
        string $dateTo,
        string $logType,
        string $logScope
    ): array {
        $must = [
            $this->buildTimeRangeFilter($timeRange, $dateFrom, $dateTo),
        ];

        $scopeFilter = $this->buildLogScopeFilter($logScope);

        if ($scopeFilter) {
            $must[] = $scopeFilter;
        }

        if ($search) {
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
                        'data.command',
                    ],
                    'default_operator' => 'and',
                ],
            ];
        }

        if ($agentId) {
            $must[] = [
                'term' => [
                    'agent.id' => $agentId,
                ],
            ];
        }

        if ($location) {
            $must[] = [
                'match_phrase' => [
                    'location' => $location,
                ],
            ];
        }

        if ($decoder) {
            $must[] = [
                'match_phrase' => [
                    'decoder.name' => $decoder,
                ],
            ];
        }

        if ($program) {
            $must[] = [
                'match_phrase' => [
                    'predecoder.program_name' => $program,
                ],
            ];
        }

        if ($logType === 'alert') {
            $must[] = [
                'exists' => [
                    'field' => 'rule.id',
                ],
            ];
        }

        if ($logType === 'raw') {
            $must[] = [
                'bool' => [
                    'must_not' => [
                        [
                            'exists' => [
                                'field' => 'rule.id',
                            ],
                        ],
                    ],
                ],
            ];
        }

        return $must;
    }

    private function buildLogScopeFilter(string $logScope): ?array
    {
        $cisConditions = [
            [
                'wildcard' => [
                    'location' => [
                        'value' => '*cis_access.log*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'wildcard' => [
                    'location' => [
                        'value' => '*cis_error.log*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'wildcard' => [
                    'location' => [
                        'value' => '*app.log*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'wildcard' => [
                    'location' => [
                        'value' => '*audit.log*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'wildcard' => [
                    'location' => [
                        'value' => '*mysql-general.log*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'wildcard' => [
                    'location' => [
                        'value' => '*mysql_general.log*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'match_phrase' => [
                    'decoder.name' => 'yii2_app_log',
                ],
            ],
            [
                'match_phrase' => [
                    'decoder.name' => 'yii2_audit_log',
                ],
            ],
            [
                'match_phrase' => [
                    'decoder.name' => 'mysql_general_log',
                ],
            ],
        ];

        if ($logScope === 'cis') {
            return [
                'bool' => [
                    'should' => $cisConditions,
                    'minimum_should_match' => 1,
                ],
            ];
        }

        if ($logScope === 'other') {
            return [
                'bool' => [
                    'must_not' => $cisConditions,
                ],
            ];
        }

        return null;
    }

    private function buildTimeRangeFilter(
        string $timeRange,
        string $dateFrom,
        string $dateTo
    ): array {
        if ($timeRange === 'custom' && $dateFrom && $dateTo) {
            return [
                'range' => [
                    'timestamp' => [
                        'gte' => $dateFrom,
                        'lte' => $dateTo,
                    ],
                ],
            ];
        }

        if ($timeRange === 'custom') {
            return [
                'range' => [
                    'timestamp' => [
                        'gte' => 'now-1h',
                        'lte' => 'now',
                    ],
                ],
            ];
        }

        $allowedTimeRanges = config('wazuh.time_ranges', [
            '15m',
            '30m',
            '1h',
            '6h',
            '24h',
            '7d',
            '30d',
        ]);

        if (!in_array($timeRange, $allowedTimeRanges, true)) {
            $timeRange = '24h';
        }

        return [
            'range' => [
                'timestamp' => [
                    'gte' => 'now-' . $timeRange,
                    'lte' => 'now',
                ],
            ],
        ];
    }

    private function buildAggregations(): array
    {
        return [
            'alert_generated' => [
                'filter' => [
                    'exists' => [
                        'field' => 'rule.id',
                    ],
                ],
            ],
            'raw_only' => [
                'filter' => [
                    'bool' => [
                        'must_not' => [
                            [
                                'exists' => [
                                    'field' => 'rule.id',
                                ],
                            ],
                        ],
                    ],
                ],
            ],
            'top_sources' => [
                'terms' => [
                    'field' => 'location',
                    'size' => 1,
                ],
            ],
            'top_decoders' => [
                'terms' => [
                    'field' => 'decoder.name',
                    'size' => 1,
                ],
            ],
            'top_programs' => [
                'terms' => [
                    'field' => 'predecoder.program_name',
                    'size' => 1,
                ],
            ],
        ];
    }

    private function getSourceFields(): array
    {
        return [
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
            'rule.description',
        ];
    }
}
