<?php

namespace App\Services;

class WazuhAlertQueryBuilder
{
    public function buildSearchPayload(
        int $page,
        int $size,
        ?string $level = null,
        ?string $search = null,
        ?string $agent = null,
        string $timeRange = '24h',
        string $dateFrom = '',
        string $dateTo = '',
        ?string $ruleId = null,
        ?string $mitre = null,
        ?string $group = null,
        string $sortBy = 'timestamp',
        string $sortOrder = 'desc',
        ?string $severity = null,
        ?int $levelGte = null
    ): array {
        return [
            'track_total_hits' => true,
            'from' => ($page - 1) * $size,
            'size' => $size,
            'query' => $this->buildQuery(
                $level,
                $search,
                $agent,
                $timeRange,
                $dateFrom,
                $dateTo,
                $ruleId,
                $mitre,
                $group,
                $severity,
                $levelGte
            ),
            'sort' => $this->buildSort($sortBy, $sortOrder),
            'aggs' => [
                'severity_summary' => [
                    'filters' => [
                        'filters' => [
                            'high' => [
                                'range' => [
                                    'rule.level' => ['gte' => 10],
                                ],
                            ],
                            'medium' => [
                                'range' => [
                                    'rule.level' => ['gte' => 5, 'lt' => 10],
                                ],
                            ],
                            'low' => [
                                'range' => [
                                    'rule.level' => ['lt' => 5],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];
    }

    private function buildQuery(
        ?string $level,
        ?string $search,
        ?string $agent,
        string $timeRange,
        string $dateFrom,
        string $dateTo,
        ?string $ruleId,
        ?string $mitre,
        ?string $group,
        ?string $severity = null,
        ?int $levelGte = null
    ): array {
        $must = [
            $this->buildTimeRangeFilter($timeRange, $dateFrom, $dateTo),
        ];

        $filters = [
            $this->buildLevelFilter($level, $levelGte, $severity),
            $this->buildSearchFilter($search),
            $this->buildAgentFilter($agent),
            $this->buildRuleIdFilter($ruleId),
            $this->buildMitreFilter($mitre),
            $this->buildGroupFilter($group),
        ];

        foreach ($filters as $filter) {
            if ($filter) {
                $must[] = $filter;
            }
        }

        return [
            'bool' => [
                'must' => $must,
            ],
        ];
    }

    private function buildTimeRangeFilter(string $timeRange, string $dateFrom, string $dateTo): array
    {
        if ($timeRange === 'custom' && $dateFrom && $dateTo) {
            return [
                'range' => [
                    '@timestamp' => [
                        'gte' => $dateFrom,
                        'lte' => $dateTo,
                    ],
                ],
            ];
        }

        // Memetakan timeframe dari frontend ke format matematika waktu Elasticsearch
        $gte = match ($timeRange) {
            'today' => 'now/d',
            '48h' => 'now-48h',
            '7d'  => 'now-7d',
            '30d' => 'now-30d',
            '15m' => 'now-15m',
            '30m' => 'now-30m',
            '1h'  => 'now-1h',
            '6h'  => 'now-6h',
            default => 'now-24h', // Nilai default jika tidak ada yang cocok
        };

        return [
            'range' => [
                '@timestamp' => [
                    'gte' => $gte,
                    'lte' => 'now',
                ],
            ],
        ];
    }

    private function buildLevelFilter(?string $level, ?int $levelGte = null, ?string $severity = null): ?array
    {
        if ($severity === 'high') {
            return ['range' => ['rule.level' => ['gte' => 10]]];
        }

        if ($severity === 'medium') {
            return ['range' => ['rule.level' => ['gte' => 5, 'lt' => 10]]];
        }

        if ($severity === 'low') {
            return ['range' => ['rule.level' => ['lt' => 5]]];
        }

        if ($levelGte !== null) {
            return ['range' => ['rule.level' => ['gte' => $levelGte]]];
        }

        if ($level !== null && is_numeric($level)) {
            return ['term' => ['rule.level' => (int) $level]];
        }

        return null;
    }

    private function buildSearchFilter(?string $search): ?array
    {
        if (!$search) {
            return null;
        }

        $search = trim($search);

        $should = [
            [
                'multi_match' => [
                    'query' => $search,
                    'fields' => [
                        'rule.description',
                        'rule.groups',
                        'rule.mitre.id',
                        'rule.mitre.technique',
                        'rule.mitre.tactic',
                        'agent.name',
                        'agent.id',
                        'manager.name',
                        'decoder.name',
                        'program_name',
                        'location',
                        'full_log',
                        'data.srcip',
                        'data.url',
                    ],
                    'lenient' => true,
                ],
            ],
            [
                'wildcard' => [
                    'rule.description.keyword' => [
                        'value' => '*' . $search . '*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'wildcard' => [
                    'agent.name.keyword' => [
                        'value' => '*' . $search . '*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'wildcard' => [
                    'decoder.name.keyword' => [
                        'value' => '*' . $search . '*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'wildcard' => [
                    'manager.name.keyword' => [
                        'value' => '*' . $search . '*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'wildcard' => [
                    'location.keyword' => [
                        'value' => '*' . $search . '*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'wildcard' => [
                    'data.srcip.keyword' => [
                        'value' => '*' . $search . '*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
            [
                'wildcard' => [
                    'data.url.keyword' => [
                        'value' => '*' . $search . '*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
        ];

        if (is_numeric($search)) {
            $should[] = ['term' => ['rule.id' => (string) $search]];
            $should[] = ['term' => ['agent.id' => (string) $search]];
        }

        return [
            'bool' => [
                'should' => $should,
                'minimum_should_match' => 1,
            ],
        ];
    }

    private function buildAgentFilter(?string $agent): ?array
    {
        if (!$agent) {
            return null;
        }

        $agent = trim($agent);

        $should = [
            ['match_phrase' => ['agent.name' => $agent]],
            [
                'wildcard' => [
                    'agent.name.keyword' => [
                        'value' => '*' . $agent . '*',
                        'case_insensitive' => true,
                    ],
                ],
            ],
        ];

        if (is_numeric($agent)) {
            $should[] = ['term' => ['agent.id' => (string) $agent]];
        }

        return [
            'bool' => [
                'should' => $should,
                'minimum_should_match' => 1,
            ],
        ];
    }

    private function buildRuleIdFilter(?string $ruleId): ?array
    {
        if (!$ruleId) {
            return null;
        }

        return [
            'term' => [
                'rule.id' => (string) trim($ruleId),
            ],
        ];
    }

    private function buildMitreFilter(?string $mitre): ?array
    {
        if (!$mitre) {
            return null;
        }

        $mitre = trim($mitre);

        return [
            'bool' => [
                'should' => [
                    ['match_phrase' => ['rule.mitre.id' => $mitre]],
                    ['match_phrase' => ['rule.mitre.technique' => $mitre]],
                    ['match_phrase' => ['rule.mitre.tactic' => $mitre]],
                    [
                        'wildcard' => [
                            'rule.mitre.id.keyword' => [
                                'value' => '*' . $mitre . '*',
                                'case_insensitive' => true,
                            ],
                        ],
                    ],
                    [
                        'wildcard' => [
                            'rule.mitre.technique.keyword' => [
                                'value' => '*' . $mitre . '*',
                                'case_insensitive' => true,
                            ],
                        ],
                    ],
                    [
                        'wildcard' => [
                            'rule.mitre.tactic.keyword' => [
                                'value' => '*' . $mitre . '*',
                                'case_insensitive' => true,
                            ],
                        ],
                    ],
                ],
                'minimum_should_match' => 1,
            ],
        ];
    }

    private function buildGroupFilter(?string $group): ?array
    {
        if (!$group) {
            return null;
        }

        $group = trim($group);

        return [
            'bool' => [
                'should' => [
                    ['match_phrase' => ['rule.groups' => $group]],
                    [
                        'wildcard' => [
                            'rule.groups.keyword' => [
                                'value' => '*' . $group . '*',
                                'case_insensitive' => true,
                            ],
                        ],
                    ],
                ],
                'minimum_should_match' => 1,
            ],
        ];
    }

    private function buildSort(string $sortBy, string $sortOrder): array
    {
        $allowedSorts = [
            'timestamp' => '@timestamp',
            'level' => 'rule.level',
            'rule_id' => 'rule.id',
            'agent_name' => 'agent.name.keyword',
        ];

        $field = $allowedSorts[$sortBy] ?? '@timestamp';
        $order = strtolower($sortOrder) === 'asc' ? 'asc' : 'desc';

        return [
            [
                $field => [
                    'order' => $order,
                    'unmapped_type' => 'keyword',
                ],
            ],
        ];
    }
}
