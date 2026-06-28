<?php

namespace App\Services;

class WazuhIndexerService
{
    public function __construct(
        private WazuhIndexerClient $indexerClient,
        private WazuhAlertQueryBuilder $alertQueryBuilder,
        private WazuhAlertMapper $alertMapper,
        private SocGeneratedAlertService $socGeneratedAlertService,
        private WazuhCriticalAlertService $criticalAlertService,
        private WazuhLogQueryBuilder $logQueryBuilder,
        private WazuhLogMapper $logMapper,
        private WazuhLogFilterService $logFilterService,
        private WazuhHealthService $healthService,
        private WazuhAgentInsightService $agentInsightService,
        private WazuhAlertCorrelationService $alertCorrelationService,
    ) {
    }

    public function getAlerts(
        $page = 1,
        $size = 20,
        $level = null,
        $search = null,
        $agent = null,
        $timeRange = '24h',
        $dateFrom = '',
        $dateTo = '',
        $ruleId = null,
        $mitre = null,
        $group = null,
        $sortBy = 'timestamp',
        $sortOrder = 'desc',
        $includeSoc = false,
        $alertView = 'incident',
        $severity = null,
        $levelGte = null
    ) {
        try {
            $page = max((int) $page, 1);
            $size = max((int) $size, 1);

            $level = $level !== '' ? $level : null;
            $search = $search !== '' ? $search : null;
            $agent = $agent !== '' ? $agent : null;
            $ruleId = $ruleId !== '' ? $ruleId : null;
            $mitre = $mitre !== '' ? $mitre : null;
            $group = $group !== '' ? $group : null;
            $severity = $severity !== '' ? $severity : null;
            $levelGte = $levelGte !== '' && $levelGte !== null ? (int) $levelGte : null;

            $queryPage = $alertView === 'raw' ? $page : 1;
            $querySize = $alertView === 'raw' ? $size : 1000;
            $queryRuleId = $alertView === 'raw' ? $ruleId : null;

            $payload = $this->alertQueryBuilder->buildSearchPayload(
                $queryPage,
                $querySize,
                $level,
                $search,
                $agent,
                $timeRange,
                $dateFrom,
                $dateTo,
                $queryRuleId,
                $mitre,
                $group,
                $sortBy,
                $sortOrder,
                $severity,
                $levelGte
            );

            $response = $this->indexerClient->post(
                '/' . config('wazuh.indexes.alerts') . '/_search',
                $payload
            );

            if (!$response->successful()) {
                return [
                    'success' => false,
                    'error' => $response->body(),
                ];
            }

            $json = $response->json();
            $hits = $json['hits']['hits'] ?? [];
            $rawTotal = data_get($json, 'hits.total.value', 0);

            $alerts = $this->alertMapper->mapMany($hits);
            $summary = $this->buildAlertSummaryFromAggregations($json, $rawTotal);

            $topMitreBuckets = data_get($json, 'aggregations.top_mitre_tactics.buckets', []);

            $topMitreStats = collect($topMitreBuckets)
                ->map(fn ($bucket) => [
                    'name' => $bucket['key'],
                    'count' => $bucket['doc_count'],
                ])
                ->toArray();

            $socAlerts = collect();

            if ($includeSoc) {
                $socAlerts = $this->socGeneratedAlertService->getAlerts(
                    $level,
                    $search,
                    $agent,
                    $timeRange,
                    $dateFrom,
                    $dateTo
                );

                $socAlerts = $this->filterSocAlerts(
                    $socAlerts,
                    $queryRuleId,
                    $mitre,
                    $group
                );

                if ($severity) {
                    $socAlerts = $this->filterSocAlertsBySeverity($socAlerts, $severity);
                }

                if ($levelGte !== null) {
                    $socAlerts = $socAlerts
                        ->filter(fn ($alert) => (int) data_get($alert, 'level', 0) >= $levelGte)
                        ->values();
                }

                $summary = $this->mergeSocAlertSummary($summary, $socAlerts);
            }

            $mergedAlerts = $includeSoc
                ? $alerts->merge($socAlerts)->sortByDesc('timestamp')->values()
                : $alerts->values();

            $correlatedAlerts = $this->alertCorrelationService
                ->correlate($mergedAlerts, $alertView)
                ->values();

            if ($alertView !== 'raw' && $ruleId) {
                $correlatedAlerts = $correlatedAlerts
                    ->filter(fn ($alert) => (string) data_get($alert, 'rule_id') === (string) $ruleId)
                    ->values();
            }

            $total = $alertView === 'raw'
                ? $rawTotal
                : $correlatedAlerts->count();

            $pagedAlerts = $alertView === 'raw'
                ? $correlatedAlerts
                : $correlatedAlerts->forPage($page, $size)->values();

            return [
                'success' => true,
                'data' => $pagedAlerts,
                'total' => $total,
                'raw_total' => $includeSoc ? $rawTotal + $socAlerts->count() : $rawTotal,
                'summary' => $summary,
                'statistics' => [
                    'top_mitre' => $topMitreStats,
                ],
                'page' => $page,
                'size' => $size,
                'total_pages' => (int) ceil(max($total, 1) / $size),
                'alert_view' => $alertView,
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    public function getAlertById(string $id): array
    {
        try {
            $response = $this->indexerClient->post(
                '/' . config('wazuh.indexes.alerts') . '/_search',
                [
                    'size' => 1,
                    'query' => [
                        'ids' => [
                            'values' => [$id],
                        ],
                    ],
                ]
            );

            if (!$response->successful()) {
                return [
                    'success' => false,
                    'error' => $response->body(),
                ];
            }

            $json = $response->json();
            $hit = $json['hits']['hits'][0] ?? null;

            if (!$hit) {
                return [
                    'success' => false,
                    'error' => 'Alert not found',
                ];
            }

            $source = $hit['_source'] ?? [];

            return [
                'success' => true,
                'data' => [
                    'id' => $hit['_id'] ?? $id,
                    'index' => $hit['_index'] ?? null,
                    'timestamp' => data_get($source, '@timestamp'),
                    'agent' => data_get($source, 'agent', []),
                    'rule' => data_get($source, 'rule', []),
                    'decoder' => data_get($source, 'decoder', []),
                    'manager' => data_get($source, 'manager', []),
                    'location' => data_get($source, 'location'),
                    'full_log' => data_get($source, 'full_log'),
                    'raw' => $source,
                ],
            ];
        } catch (\Throwable $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    public function getCriticalAlertsForNotifications($level = 10, $size = 20)
    {
        return $this->criticalAlertService->getForNotifications($level, $size);
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
        $dateTo = '',
        $logType = '',
        $logScope = 'cis'
    ) {
        try {
            $page = max((int) $page, 1);
            $size = max((int) $size, 1);

            $payload = $this->logQueryBuilder->buildSearchPayload(
                $page,
                $size,
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
            );

            $response = $this->indexerClient->post(
                '/' . config('wazuh.indexes.archives') . '/_search',
                $payload
            );

            if (!$response->successful()) {
                return [
                    'success' => false,
                    'error' => $response->body(),
                ];
            }

            $json = $response->json();

            $hits = $json['hits']['hits'] ?? [];
            $total = data_get($json, 'hits.total.value', 0);
            $totalRelation = data_get($json, 'hits.total.relation', 'eq');
            $aggs = $json['aggregations'] ?? [];

            return [
                'success' => true,
                'data' => $this->logMapper->mapMany($hits),
                'total' => $total,
                'total_relation' => $totalRelation,
                'page' => $page,
                'size' => $size,
                'total_pages' => (int) ceil(max($total, 1) / $size),
                'insights' => $this->buildLogInsights($aggs),
                'log_scope' => $logScope,
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    public function getLogFilters()
    {
        return $this->logFilterService->getFilters();
    }

    public function getHealthSummary()
    {
        return $this->healthService->getSummary();
    }

    public function getAgentInsightMap($agentIds = [])
    {
        return $this->agentInsightService->getInsightMap($agentIds);
    }

    private function buildAlertSummaryFromAggregations(array $json, int $total): array
    {
        $summaryBuckets = data_get($json, 'aggregations.severity_summary.buckets', []);

        return [
            'total' => $total,
            'high' => data_get($summaryBuckets, 'high.doc_count', 0),
            'medium' => data_get($summaryBuckets, 'medium.doc_count', 0),
            'low' => data_get($summaryBuckets, 'low.doc_count', 0),
        ];
    }

    private function filterSocAlertsBySeverity($alerts, string $severity)
    {
        return $alerts
            ->filter(function ($alert) use ($severity) {
                $level = (int) data_get($alert, 'level', 0);

                return match ($severity) {
                    'critical' => $level >= 14 && $level <= 15,
                    'high' => $level >= 10 && $level <= 13,
                    'medium' => $level >= 5 && $level < 10,
                    'low' => $level < 5,
                    default => true,
                };
            })
            ->values();
    }

    private function filterSocAlerts($socAlerts, ?string $ruleId, ?string $mitre, ?string $group)
    {
        return $socAlerts->filter(function ($alert) use ($ruleId, $mitre, $group) {
            if ($ruleId && (string) data_get($alert, 'rule_id') !== (string) $ruleId) {
                return false;
            }

            if ($group) {
                $groups = data_get($alert, 'groups', []);

                if (!is_array($groups)) {
                    $groups = [$groups];
                }

                $matched = collect($groups)->contains(function ($item) use ($group) {
                    return str_contains(strtolower((string) $item), strtolower($group));
                });

                if (!$matched) {
                    return false;
                }
            }

            if ($mitre) {
                $mitreText = strtolower($mitre);

                $mitreFields = collect([
                    data_get($alert, 'mitre_id', []),
                    data_get($alert, 'tactic', []),
                    data_get($alert, 'technique', []),
                ])
                    ->flatten()
                    ->map(fn ($item) => strtolower((string) $item))
                    ->implode(' ');

                if (!str_contains($mitreFields, $mitreText)) {
                    return false;
                }
            }

            return true;
        })->values();
    }

    private function mergeSocAlertSummary(array $summary, $socAlerts): array
    {
        $summary['total'] += $socAlerts->count();
        $summary['high'] += $socAlerts->where('level', '>=', 10)->count();
        $summary['medium'] += $socAlerts->where('level', '>=', 5)->where('level', '<', 10)->count();
        $summary['low'] += $socAlerts->where('level', '<', 5)->count();

        return $summary;
    }

    private function buildLogInsights(array $aggs): array
    {
        return [
            'alert_generated' => data_get($aggs, 'alert_generated.doc_count', 0),
            'raw_only' => data_get($aggs, 'raw_only.doc_count', 0),
            'top_source' => data_get($aggs, 'top_sources.buckets.0.key', '-'),
            'top_source_count' => data_get($aggs, 'top_sources.buckets.0.doc_count', 0),
            'top_decoder' => data_get($aggs, 'top_decoders.buckets.0.key', '-'),
            'top_decoder_count' => data_get($aggs, 'top_decoders.buckets.0.doc_count', 0),
            'top_program' => data_get($aggs, 'top_programs.buckets.0.key', '-'),
            'top_program_count' => data_get($aggs, 'top_programs.buckets.0.doc_count', 0),
        ];
    }
}
