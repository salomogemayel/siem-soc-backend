<?php

namespace App\Services;

use App\Models\UnusualIpAlert;
use Illuminate\Support\Collection;

class SocGeneratedAlertService
{
    public function getAlerts(
        $level = null,
        $search = null,
        $agent = null,
        $timeRange = '24h',
        $dateFrom = '',
        $dateTo = ''
    ): Collection {
        if (!$this->matchesLevelFilter($level)) {
            return collect();
        }

        if (!$this->matchesAgentFilter($agent)) {
            return collect();
        }

        $alerts = $this->queryAlerts($search)
            ->get()
            ->map(function ($alert) {
                return $this->mapAlert($alert);
            });

        return $this->filterByTimeRange($alerts, $timeRange, $dateFrom, $dateTo);
    }

    private function queryAlerts($search)
    {
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

        return $query;
    }

    private function mapAlert(UnusualIpAlert $alert): array
    {
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
    }

    private function filterByTimeRange(
        Collection $alerts,
        string $timeRange,
        string $dateFrom,
        string $dateTo
    ): Collection {
        if ($timeRange !== 'custom' || !$dateFrom || !$dateTo) {
            return $alerts;
        }

        return $alerts->filter(function ($alert) use ($dateFrom, $dateTo) {
            $timestamp = data_get($alert, 'timestamp');

            if (!$timestamp) {
                return false;
            }

            return strtotime($timestamp) >= strtotime($dateFrom)
                && strtotime($timestamp) <= strtotime($dateTo);
        })->values();
    }

    private function matchesAgentFilter($agent): bool
    {
        if (!$agent) {
            return true;
        }

        return str_contains(strtolower('SOC Analysis'), strtolower($agent))
            || str_contains(strtolower('SOC'), strtolower($agent));
    }

    private function matchesLevelFilter($level): bool
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
}
