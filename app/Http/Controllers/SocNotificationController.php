<?php

namespace App\Http\Controllers;

use App\Models\SocNotification;
use App\Models\UnusualIpAlert;
use App\Services\WazuhIndexerService;
use Illuminate\Http\Request;

class SocNotificationController extends Controller
{
    protected $wazuhIndexerService;

    public function __construct(WazuhIndexerService $wazuhIndexerService)
    {
        $this->wazuhIndexerService = $wazuhIndexerService;
    }

    private function syncCriticalAlerts(Request $request): void
    {
        $user = $request->user();

        if (!$user) {
            return;
        }

        $result = $this->wazuhIndexerService->getCriticalAlertsForNotifications(10, 30);

        if (!($result['success'] ?? false)) {
            return;
        }

        foreach (($result['data'] ?? []) as $alert) {
            $sourceAlertId = data_get($alert, 'source_alert_id', data_get($alert, 'id'));

            if (!$sourceAlertId) {
                continue;
            }

            $level = (int) data_get($alert, 'rule_level', data_get($alert, 'level', 0));
            $severity = $level >= 12 ? 'critical' : 'high';

            SocNotification::updateOrCreate(
                [
                    'user_id' => $user->id,
                    'source_alert_id' => $sourceAlertId,
                ],
                [
                    'type' => 'critical_alert',
                    'title' => $severity === 'critical'
                        ? 'Critical Alert Detected'
                        : 'High Severity Alert Detected',
                    'message' => data_get($alert, 'description', 'Security alert detected'),
                    'severity' => $severity,
                    'rule_id' => data_get($alert, 'rule_id'),
                    'rule_level' => $level,
                    'agent_id' => data_get($alert, 'agent_id'),
                    'agent_name' => data_get($alert, 'agent_name'),
                    'alert_timestamp' => data_get($alert, 'timestamp', now()),
                    'metadata' => $alert,
                ]
            );
        }

        $unusualIpAlerts = UnusualIpAlert::where('status', 'new')
            ->latest()
            ->limit(30)
            ->get();

        foreach ($unusualIpAlerts as $alert) {
            SocNotification::updateOrCreate(
                [
                    'user_id' => $user->id,
                    'source_alert_id' => 'soc-unusual-ip-' . $alert->id,
                ],
                [
                    'type' => 'unusual_ip',
                    'title' => 'Unusual IP Login Detected',
                    'message' => "CIS user {$alert->cis_user_id} logged in from new IP {$alert->ip_address}",
                    'severity' => 'high',
                    'rule_id' => 'SOC-UNUSUAL-IP',
                    'rule_level' => 10,
                    'agent_id' => 'SOC',
                    'agent_name' => 'SOC Analysis',
                    'alert_timestamp' => $alert->detected_at ?? now(),
                    'metadata' => [
                        'soc_alert_id' => $alert->id,
                        'cis_user_id' => $alert->cis_user_id,
                        'ip_address' => $alert->ip_address,
                        'wazuh_alert_id' => $alert->wazuh_alert_id,
                        'wazuh_rule_id' => $alert->wazuh_rule_id,
                        'reason' => $alert->reason,
                        'status' => $alert->status,
                    ],
                ]
            );
        }
    }

    public function index(Request $request)
    {
        $this->syncCriticalAlerts($request);

        $size = (int) $request->query('size', 10);

        $notifications = SocNotification::where('user_id', $request->user()->id)
            ->latest()
            ->paginate($size);

        $unread = SocNotification::where('user_id', $request->user()->id)
            ->where('is_read', false)
            ->count();

        return response()->json([
            'success' => true,
            'data' => $notifications->items(),
            'total' => $notifications->total(),
            'page' => $notifications->currentPage(),
            'total_pages' => $notifications->lastPage(),
            'unread' => $unread,
        ]);
    }

    public function unreadCount(Request $request)
    {
        $this->syncCriticalAlerts($request);

        $count = SocNotification::where('user_id', $request->user()->id)
            ->where('is_read', false)
            ->count();

        return response()->json([
            'success' => true,
            'count' => $count,
        ]);
    }

    public function markAsRead(Request $request, $id)
    {
        $notification = SocNotification::where('user_id', $request->user()->id)
            ->where('id', $id)
            ->firstOrFail();

        $notification->update([
            'is_read' => true,
            'read_at' => now(),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Notification marked as read',
        ]);
    }

    public function markAllAsRead(Request $request)
    {
        SocNotification::where('user_id', $request->user()->id)
            ->where('is_read', false)
            ->update([
                'is_read' => true,
                'read_at' => now(),
            ]);

        return response()->json([
            'success' => true,
            'message' => 'All notifications marked as read',
        ]);
    }
}
