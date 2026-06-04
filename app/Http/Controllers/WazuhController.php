<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\WazuhApiService;
use App\Services\WazuhIndexerService;

class WazuhController extends Controller
{
    protected $wazuhApiService;
    protected $wazuhIndexerService;

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

        $agentsResponse = $this->wazuhApiService->getAgents(
            $page,
            $size,
            $search,
            $status
        );

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

        $rules = $this->wazuhApiService->getRules(
            $page,
            $size,
            $search,
            $level,
            $group
        );

        return response()->json($rules);
    }

    public function alerts(Request $request)
    {
        $page = $request->query('page', 1);
        $size = $request->query('size', 20);
        $level = $request->query('level');
        $search = $request->query('search');
        $agent = $request->query('agent');

        return response()->json(
            $this->wazuhIndexerService->getAlerts($page, $size, $level, $search, $agent)
        );
    }

    public function manager()
    {
        $manager = $this->wazuhApiService->getManagerInfo();
        $indexer = $this->wazuhIndexerService->getHealthSummary();
        $agents = $this->wazuhApiService->getAgentsHealthSummary();

        if (!($manager['success'] ?? false)) {
            return response()->json([
                'success' => false,
                'error' => $manager['error'] ?? 'Failed to load manager information'
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
            ]
        ]);
    }



    public function logs(Request $request)
    {
        $page = (int) $request->query('page', 1);
        $size = (int) $request->query('size', 20);
        $search = $request->query('search', '');
        $agentId = $request->query('agent_id', '');
        $location = $request->query('location', '');
        $decoder = $request->query('decoder', '');
        $program = $request->query('program', '');
        $timeRange = $request->query('time_range', '24h');
        $dateFrom = $request->query('date_from', '');
        $dateTo = $request->query('date_to', '');

        return response()->json(
            $this->wazuhIndexerService->getLogs(
                $page,
                $size,
                $search,
                $agentId,
                $location,
                $decoder,
                $program,
                $timeRange,
                $dateFrom,
                $dateTo
            )
        );
    }

    public function logFilters()
    {
        return response()->json(
            $this->wazuhIndexerService->getLogFilters()
        );
    }
}
