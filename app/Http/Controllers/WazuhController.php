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
        $size = (int) $request->query('size', 20);
        $search = $request->query('search', '');
        $status = $request->query('status', '');

        return response()->json(
            $this->wazuhApiService->getAgents($page, $size, $search, $status)
        );
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
        return response()->json(
            $this->wazuhApiService->getManagerInfo()
        );
    }
}
