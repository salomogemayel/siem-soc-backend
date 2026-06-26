<?php

namespace App\Services;

use Illuminate\Support\Collection;

class WazuhAlertCorrelationService
{
    private const PARENT_CHILD_RULES = [
        '100101' => ['100100'],
        '100104' => ['100103'],
        '100201' => ['100200'],
        '100212' => ['100211'],
        '100221' => ['100220'],
        '100231' => ['100230'],
    ];

    public function correlate(Collection $alerts, string $view = 'incident'): Collection
    {
        $alerts = $alerts
            ->map(fn ($alert) => $this->prepareAlert($alert))
            ->sortByDesc('timestamp')
            ->values();

        if ($view === 'raw') {
            return $alerts;
        }

        $parents = $alerts
            ->filter(fn ($alert) => $this->isParentRule($alert))
            ->map(function ($parent) use ($alerts) {
                return $this->attachChildAlerts($parent, $alerts);
            })
            ->values();

        if ($view === 'evidence') {
            return $parents;
        }

        $standaloneAlerts = $alerts
            ->reject(fn ($alert) => $this->isChildRule($alert))
            ->reject(fn ($alert) => $this->isParentRule($alert))
            ->values();

        return $parents
            ->merge($standaloneAlerts)
            ->sortByDesc('timestamp')
            ->values();
    }

    private function prepareAlert(array $alert): array
    {
        $ruleId = (string) data_get($alert, 'rule_id', '-');

        return [
            ...$alert,
            'correlation_role' => $this->getCorrelationRole($ruleId),
            'correlation_parent_rule_id' => $this->getParentRuleId($ruleId),
            'child_alerts' => data_get($alert, 'child_alerts', []),
            'child_count' => data_get($alert, 'child_count', 0),
        ];
    }

    private function attachChildAlerts(array $parent, Collection $alerts): array
    {
        $parentRuleId = (string) data_get($parent, 'rule_id');
        $childRuleIds = self::PARENT_CHILD_RULES[$parentRuleId] ?? [];

        $parentTimestamp = strtotime((string) data_get($parent, 'timestamp'));
        $parentSrcip = (string) data_get($parent, 'srcip', '-');

        $children = $alerts
            ->filter(function ($alert) use ($childRuleIds, $parentTimestamp, $parentSrcip) {
                $ruleId = (string) data_get($alert, 'rule_id');
                $srcip = (string) data_get($alert, 'srcip', '-');
                $timestamp = strtotime((string) data_get($alert, 'timestamp'));

                if (!in_array($ruleId, $childRuleIds, true)) {
                    return false;
                }

                if ($parentSrcip !== '-' && $srcip !== '-' && $parentSrcip !== $srcip) {
                    return false;
                }

                if (!$timestamp || !$parentTimestamp) {
                    return false;
                }

                return abs($parentTimestamp - $timestamp) <= 120;
            })
            ->values();

        return [
            ...$parent,
            'correlation_role' => 'parent',
            'child_alerts' => $children->all(),
            'child_count' => $children->count(),
        ];
    }

    private function isParentRule(array $alert): bool
    {
        return array_key_exists((string) data_get($alert, 'rule_id'), self::PARENT_CHILD_RULES);
    }

    private function isChildRule(array $alert): bool
    {
        return $this->getParentRuleId((string) data_get($alert, 'rule_id')) !== null;
    }

    private function getCorrelationRole(string $ruleId): string
    {
        if (array_key_exists($ruleId, self::PARENT_CHILD_RULES)) {
            return 'parent';
        }

        if ($this->getParentRuleId($ruleId)) {
            return 'child';
        }

        return 'standalone';
    }

    private function getParentRuleId(string $ruleId): ?string
    {
        foreach (self::PARENT_CHILD_RULES as $parentRuleId => $childRuleIds) {
            if (in_array($ruleId, $childRuleIds, true)) {
                return $parentRuleId;
            }
        }

        return null;
    }
}
