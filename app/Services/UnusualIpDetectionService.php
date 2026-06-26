<?php

namespace App\Services;

use App\Models\ProcessedLoginAlert;
use App\Models\SocNotification;
use App\Models\UserIpBaseline;
use App\Models\UnusualIpAlert;
use Carbon\Carbon;

class UnusualIpDetectionService
{
    public function processLoginAlert(array $alert): array
    {
        $cisUserId = data_get($alert, 'raw.data.yii_user_id', data_get($alert, 'yii_user_id'));
        $ipAddress = data_get($alert, 'srcip')
            ?? data_get($alert, 'raw.srcip')
            ?? 'UNKNOWN';

        logger()->info('DEBUG IP DETECTION', [
            'cis_user_id' => $cisUserId,
            'ip_address' => $ipAddress,
            'raw' => $alert,
        ]);
        $wazuhAlertId = data_get($alert, 'id');
        $wazuhRuleId = data_get($alert, 'rule.id');
        $timestamp = data_get($alert, 'timestamp');

        if (!$cisUserId || !$ipAddress) {
            return [
                'status' => 'skipped',
                'reason' => 'Missing cis_user_id or ip_address',
            ];
        }

        if ($wazuhAlertId && ProcessedLoginAlert::where('wazuh_alert_id', $wazuhAlertId)->exists()) {
            return [
                'status' => 'skipped',
                'reason' => 'Login alert already processed',
            ];
        }

        $detectedAt = $timestamp ? Carbon::parse($timestamp) : now();

        $existingBaseline = UserIpBaseline::where('cis_user_id', $cisUserId)
            ->where('ip_address', $ipAddress)
            ->first();

        if ($existingBaseline) {
            $existingBaseline->update([
                'last_seen_at' => $detectedAt,
                'login_count' => $existingBaseline->login_count + 1,
            ]);

            return [
                'status' => 'normal',
                'reason' => 'Known IP',
                'notify' => false
            ];
        }

        $hasAnyBaseline = UserIpBaseline::where('cis_user_id', $cisUserId)->exists();

        $baseline = UserIpBaseline::create([
            'cis_user_id' => $cisUserId,
            'ip_address' => $ipAddress,
            'first_seen_at' => $detectedAt,
            'last_seen_at' => $detectedAt,
            'login_count' => 1,
            'is_trusted' => !$hasAnyBaseline,
        ]);

        if (!$hasAnyBaseline || $this->isRecentlyReset($cisUserId, $ipAddress)) {
            $this->markAsProcessed($wazuhAlertId, $wazuhRuleId, $cisUserId, $ipAddress);

            return [
                'status' => 'baseline_created',
                'reason' => 'First known IP for this CIS user',
                'baseline' => $baseline,
            ];
        }

        $unusualAlert = UnusualIpAlert::create([
            'cis_user_id' => $cisUserId,
            'ip_address' => $ipAddress,
            'wazuh_alert_id' => $wazuhAlertId,
            'wazuh_rule_id' => $wazuhRuleId,
            'detected_at' => $detectedAt,
            'reason' => 'New IP address for this CIS user',
            'status' => 'new',
        ]);

        SocNotification::create([
            'user_id' => null,
            'source_alert_id' => $unusualAlert->id,
            'type' => 'unusual_ip',
            'title' => 'Unusual IP Login Detected',
            'message' => "CIS user {$cisUserId} logged in from a new IP address: {$ipAddress}.",
            'severity' => 'medium',
            'rule_id' => $wazuhRuleId,
            'rule_level' => 6,
            'agent_id' => data_get($alert, 'agent.id'),
            'agent_name' => data_get($alert, 'agent.name'),
            'alert_timestamp' => $detectedAt,
            'is_read' => false,
            'metadata' => [
                'cis_user_id' => $cisUserId,
                'ip_address' => $ipAddress,
                'unusual_ip_alert_id' => $unusualAlert->id,
                'wazuh_alert_id' => $wazuhAlertId,
            ],
        ]);

        $this->markAsProcessed($wazuhAlertId, $wazuhRuleId, $cisUserId, $ipAddress);

        return [
            'status' => 'unusual',
            'reason' => 'New IP address for this CIS user',
            'alert' => $unusualAlert,
        ];
    }

    private function markAsProcessed(
        ?string $wazuhAlertId,
        ?string $wazuhRuleId,
        string $cisUserId,
        string $ipAddress
    ): void {
        if (!$wazuhAlertId) {
            return;
        }

        ProcessedLoginAlert::firstOrCreate(
            [
                'wazuh_alert_id' => $wazuhAlertId,
            ],
            [
                'wazuh_rule_id' => $wazuhRuleId,
                'cis_user_id' => $cisUserId,
                'ip_address' => $ipAddress,
                'processed_at' => now(),
            ]
        );
    }

    private function isRecentlyReset(string $cisUserId, string $ipAddress): bool
    {
        return UserIpBaseline::where('cis_user_id', $cisUserId)
            ->where('ip_address', $ipAddress)
            ->where('updated_at', '>=', now()->subMinutes(10))
            ->doesntExist();
    }
}
