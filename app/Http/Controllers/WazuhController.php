<?php

namespace App\Http\Controllers;

use App\Http\Requests\GetWazuhAlertsRequest;
use App\Http\Requests\GetWazuhLogsRequest;
use App\Http\Resources\WazuhAlertResource;
use App\Http\Resources\WazuhLogResource;
use App\Services\WazuhApiService;
use App\Services\WazuhIndexerService;
use Illuminate\Http\Request;

class WazuhController extends Controller
{
    protected WazuhApiService $wazuhApiService;
    protected WazuhIndexerService $wazuhIndexerService;

    public function __construct(
        WazuhApiService $wazuhApiService,
        WazuhIndexerService $wazuhIndexerService
    ) {
        $this->wazuhApiService = $wazuhApiService;
        $this->wazuhIndexerService = $wazuhIndexerService;
    }

    public function agents(Request $request)
    {
        $page = (int) $request->query('page', 1);
        $size = (int) $request->query('size', 100);
        $search = $request->query('search', '');
        $status = $request->query('status', '');

        $agentsResponse = $this->wazuhApiService->getAgents($page, $size, $search, $status);

        if (!$agentsResponse['success']) {
            return response()->json($agentsResponse);
        }

        $agents = $agentsResponse['data']['affected_items'] ?? [];

        $agentIds = collect($agents)
            ->pluck('id')
            ->filter()
            ->values()
            ->toArray();

        $insightMap = $this->wazuhIndexerService->getAgentInsightMap($agentIds);

        $agents = collect($agents)->map(function ($agent) use ($insightMap) {
            $id = $agent['id'] ?? null;

            $insight = $insightMap[$id] ?? [
                'alerts_24h' => 0,
                'high_alerts_24h' => 0,
                'latest_alert_at' => null,
                'latest_log_at' => null,
                'latest_data_at' => null,
                'risk_level' => 'Low',
            ];

            if (($agent['status'] ?? '') !== 'active') {
                $insight['risk_level'] = 'High';
            }

            $agent['insights'] = $insight;

            return $agent;
        })->values();

        $agentsResponse['data']['affected_items'] = $agents;

        return response()->json($agentsResponse);
    }

    public function rules(Request $request)
    {
        $page = (int) $request->query('page', 1);
        $size = (int) $request->query('size', 20);
        $search = $request->query('search', '');
        $level = $request->query('level', '');
        $group = $request->query('group', '');
        $ruleType = $request->query('ruleType', 'custom');

        return response()->json(
            $this->wazuhApiService->getRules($page, $size, $search, $level, $group, $ruleType)
        );
    }

    public function alerts(GetWazuhAlertsRequest $request)
    {
        $filters = $request->filters();

        $result = $this->wazuhIndexerService->getAlerts(
            $filters['page'],
            $filters['size'],
            $filters['level'],
            $filters['search'],
            $filters['agentId'],
            $filters['timeRange'],
            $filters['dateFrom'],
            $filters['dateTo'],
            $filters['ruleId'],
            $filters['mitre'],
            $filters['group'],
            $filters['sortBy'],
            $filters['sortOrder'],
            $filters['includeSoc'],
            $filters['alertView'],
            $filters['severity'],
            $filters['levelGte']
        );

        if (!($result['success'] ?? false)) {
            return response()->json($result, 500);
        }

        $result['data'] = WazuhAlertResource::collection($result['data'])->resolve();

        return response()->json($result);
    }

    public function alertDetail(string $id)
    {
        $result = $this->wazuhIndexerService->getAlertById($id);

        if (!($result['success'] ?? false)) {
            return response()->json($result, 404);
        }

        return response()->json($result);
    }

    public function manager()
    {
        $manager = $this->wazuhApiService->getManagerInfo();
        $indexer = $this->wazuhIndexerService->getHealthSummary();
        $agents = $this->wazuhApiService->getAgentsHealthSummary();

        if (!($manager['success'] ?? false)) {
            return response()->json([
                'success' => false,
                'error' => $manager['error'] ?? 'Failed to load manager information',
            ]);
        }

        return response()->json([
            'success' => true,
            'data' => [
                'status' => $manager['data']['status'] ?? [],
                'info' => $manager['data']['info'] ?? [],
                'health' => [
                    'manager_api' => 'online',
                    'indexer' => $indexer['health']['indexer'] ?? 'error',
                    'alerts_pipeline' => $indexer['health']['alerts_pipeline'] ?? 'idle',
                    'logs_pipeline' => $indexer['health']['logs_pipeline'] ?? 'idle',
                ],
                'metrics' => array_merge(
                    $indexer['metrics'] ?? [],
                    $agents
                ),
                'latest' => $indexer['latest'] ?? [],
                'indices' => $indexer['indices'] ?? [],
            ],
        ]);
    }

    public function logs(GetWazuhLogsRequest $request)
    {
        $filters = $request->filters();

        $result = $this->wazuhIndexerService->getLogs(
            $filters['page'],
            $filters['size'],
            $filters['search'],
            $filters['agentId'],
            $filters['location'],
            $filters['decoder'],
            $filters['program'],
            $filters['timeRange'],
            $filters['dateFrom'],
            $filters['dateTo'],
            $filters['logType'],
            $filters['logScope'] ?? 'cis'
        );

        if (!($result['success'] ?? false)) {
            return response()->json($result, 500);
        }

        $result['data'] = WazuhLogResource::collection($result['data'])->resolve();

        return response()->json($result);
    }

    public function logFilters()
    {
        return response()->json($this->wazuhIndexerService->getLogFilters());
    }
}
