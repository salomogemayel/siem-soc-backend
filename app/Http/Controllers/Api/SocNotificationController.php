<?php

namespace App\Http\Controllers\Api;

use App\Models\UnusualIpAlert;
use App\Http\Controllers\Controller;
use App\Models\SocNotification;
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
        $result = $this->wazuhIndexerService->getCriticalAlertsForNotifications(10, 30);

        if (!$result['success']) {
            return;
        }

        foreach ($result['data'] as $alert) {
            $level = (int) $alert['rule_level'];

            $severity = $level >= 12 ? 'critical' : 'high';

            SocNotification::updateOrCreate(
                [
                    'user_id' => $request->user()->id,
                    'source_alert_id' => $alert['source_alert_id'],
                ],
                [
                    'type' => 'critical_alert',
                    'title' => $severity === 'critical'
                        ? 'Critical Alert Detected'
                        : 'High Severity Alert Detected',
                    'message' => $alert['description'],
                    'severity' => $severity,
                    'rule_id' => $alert['rule_id'],
                    'rule_level' => $level,
                    'agent_id' => $alert['agent_id'],
                    'agent_name' => $alert['agent_name'],
                    'alert_timestamp' => $alert['timestamp'],
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
                    'user_id' => $request->user()->id,
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
                    'alert_timestamp' => $alert->detected_at,
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
