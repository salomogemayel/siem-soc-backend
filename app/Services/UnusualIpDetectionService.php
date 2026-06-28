<?php

namespace App\Services;

use App\Models\ProcessedLoginAlert;
use App\Models\SocNotification;
use App\Models\UserIpBaseline;
use App\Models\UnusualIpAlert;
use Carbon\Carbon;
use Illuminate\Support\Facades\Log;

class UnusualIpDetectionService
{
    public function processLoginAlert(array $alert): array
    {
        $cisUserId = data_get($alert, 'data.yii_user_id', data_get($alert, 'yii_user_id'));

        $ipAddress = data_get($alert, 'data.srcip')
            ?? data_get($alert, 'srcip')
            ?? 'UNKNOWN';

        $messageRaw = data_get($alert, 'data.yii_message', '');
        $device = 'UNKNOWN';
        if (preg_match('/device=([^\s]+)/', $messageRaw, $matches)) {
            $device = $matches[1];
        }

        $wazuhAlertId = data_get($alert, 'id');
        $wazuhRuleId = data_get($alert, 'rule.id');
        $timestamp = data_get($alert, 'timestamp');

        if (!$cisUserId || $ipAddress === 'UNKNOWN') {
            return ['status' => 'skipped', 'reason' => 'Missing cis_user_id or ip_address'];
        }

        if ($wazuhAlertId && ProcessedLoginAlert::where('wazuh_alert_id', $wazuhAlertId)->exists()) {
            return ['status' => 'skipped', 'reason' => 'Login alert already processed'];
        }

        $detectedAt = $timestamp ? Carbon::parse($timestamp) : now();

        $existingBaseline = UserIpBaseline::where('cis_user_id', $cisUserId)
            ->where('ip_address', $ipAddress)
            ->where('device', $device)
            ->first();

        if ($existingBaseline) {
            $existingBaseline->update([
                'last_seen_at' => $detectedAt,
                'login_count' => $existingBaseline->login_count + 1,
            ]);
            $this->markAsProcessed($wazuhAlertId, $wazuhRuleId, $cisUserId, $ipAddress, $device);

            return ['status' => 'normal', 'reason' => 'Known IP and Device combination', 'notify' => false];
        }

        $hasAnyBaseline = UserIpBaseline::where('cis_user_id', $cisUserId)->exists();

        $baseline = UserIpBaseline::create([
            'cis_user_id' => $cisUserId,
            'ip_address' => $ipAddress,
            'device' => $device,
            'first_seen_at' => $detectedAt,
            'last_seen_at' => $detectedAt,
            'login_count' => 1,
            'is_trusted' => !$hasAnyBaseline,
        ]);

        if (!$hasAnyBaseline || $this->isRecentlyReset($cisUserId, $ipAddress, $device)) {
            $this->markAsProcessed($wazuhAlertId, $wazuhRuleId, $cisUserId, $ipAddress, $device);

            return ['status' => 'baseline_created', 'reason' => 'First known IP/Device registered', 'baseline' => $baseline];
        }

        // ======================================================================
        // LOGIKA PENENTUAN JENIS ANOMALI (IP Baru, Device Baru, atau Keduanya)
        // ======================================================================
        $ipExists = UserIpBaseline::where('cis_user_id', $cisUserId)->where('ip_address', $ipAddress)->exists();
        $deviceExists = UserIpBaseline::where('cis_user_id', $cisUserId)->where('device', $device)->exists();

        $anomalyReason = 'New IP Address and Device';
        $notifMessage = "User [{$cisUserId}] logged in from a completely new IP and Device.\nIP: {$ipAddress}\nDevice: {$device}";

        if (!$ipExists && $deviceExists) {
            $anomalyReason = 'New IP Address';
            $notifMessage = "User [{$cisUserId}] logged in from a recognized Device but a NEW IP Address.\nIP: {$ipAddress}\nDevice: {$device}";
        } elseif ($ipExists && !$deviceExists) {
            $anomalyReason = 'New Device';
            $notifMessage = "User [{$cisUserId}] logged in from a recognized IP but a NEW Device.\nIP: {$ipAddress}\nDevice: {$device}";
        }

        $unusualAlert = UnusualIpAlert::create([
            'cis_user_id' => $cisUserId,
            'ip_address' => $ipAddress,
            'device' => $device,
            'wazuh_alert_id' => $wazuhAlertId,
            'wazuh_rule_id' => $wazuhRuleId,
            'detected_at' => $detectedAt,
            'reason' => $anomalyReason, // Menyimpan alasan dinamis ke DB
            'status' => 'new',
        ]);

        try {
            SocNotification::create([
                'source_alert_id' => (string) $unusualAlert->id,
                'type' => 'unusual_access',
                'title' => 'Unusual Login Detected',
                'message' => $notifMessage, // Menggunakan pesan dinamis
                'severity' => 'medium',
                'rule_id' => $wazuhRuleId,
                'rule_level' => 6,
                'agent_id' => data_get($alert, 'agent.id', '000'),
                'agent_name' => data_get($alert, 'agent.name', 'wazuh-manager'),
                'alert_timestamp' => $detectedAt,
                'is_read' => false,
                'metadata' => [
                    'cis_user_id' => $cisUserId,
                    'ip_address' => $ipAddress,
                    'device' => $device,
                    'anomaly_type' => $anomalyReason,
                    'wazuh_alert_id' => $wazuhAlertId,
                ],
            ]);
        } catch (\Exception $e) {
            Log::error('Gagal membuat Notifikasi SOC: ' . $e->getMessage());
        }

        $this->markAsProcessed($wazuhAlertId, $wazuhRuleId, $cisUserId, $ipAddress, $device);

        return ['status' => 'unusual', 'reason' => $anomalyReason, 'alert' => $unusualAlert];
    }

    private function markAsProcessed(?string $wazuhAlertId, ?string $wazuhRuleId, string $cisUserId, string $ipAddress, string $device): void
    {
        if (!$wazuhAlertId) return;

        ProcessedLoginAlert::firstOrCreate(
            ['wazuh_alert_id' => $wazuhAlertId],
            [
                'wazuh_rule_id' => $wazuhRuleId,
                'cis_user_id' => $cisUserId,
                'ip_address' => $ipAddress,
                'device' => $device,
                'processed_at' => now(),
            ]
        );
    }

    private function isRecentlyReset(string $cisUserId, string $ipAddress, string $device): bool
    {
        return UserIpBaseline::where('cis_user_id', $cisUserId)
            ->where('ip_address', $ipAddress)
            ->where('device', $device)
            ->where('updated_at', '>=', now()->subMinutes(10))
            ->doesntExist();
    }
}
