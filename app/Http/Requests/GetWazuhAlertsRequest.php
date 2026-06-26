<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class GetWazuhAlertsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    protected function prepareForValidation(): void
    {
        $this->merge([
            'time_range' => $this->input('time_range', $this->input('timeRange', '24h')),
            'date_from' => $this->input('date_from', $this->input('dateFrom')),
            'date_to' => $this->input('date_to', $this->input('dateTo')),
            'rule_id' => $this->input('rule_id', $this->input('ruleId')),
            'agent_id' => $this->input('agent_id', $this->input('agentId', $this->input('agent'))),
            'sort_by' => $this->input('sort_by', $this->input('sortBy', 'timestamp')),
            'sort_order' => $this->input('sort_order', $this->input('sortOrder', 'desc')),
            'include_soc' => $this->boolean('include_soc') || $this->boolean('includeSoc'),
        ]);
    }

    public function rules(): array
    {
        return [
            'page' => 'nullable|integer|min:1',
            'size' => 'nullable|integer|min:1|max:10000',
            'level' => 'nullable|string',
            'level_gte' => 'nullable|integer|min:0|max:15',
            'severity' => 'nullable|in:low,medium,high,critical',
            'search' => 'nullable|string|max:255',
            'agent_id' => 'nullable|string|max:50',
            'rule_id' => 'nullable|string|max:50',
            'mitre' => 'nullable|string|max:100',
            'group' => 'nullable|string|max:100',
            'time_range' => 'nullable|in:15m,30m,1h,6h,24h,7d,30d,custom,today',
            'date_from' => 'nullable|date',
            'date_to' => 'nullable|date',
            'sort_by' => 'nullable|in:timestamp,level,rule_id,agent_name',
            'sort_order' => 'nullable|in:asc,desc',
            'include_soc' => 'nullable|boolean',
            'alert_view' => 'nullable|in:incident,evidence,raw',
        ];
    }

    public function filters(): array
    {
        return [
            'page' => (int) $this->query('page', 1),
            'size' => (int) $this->query('size', 20),
            'level' => $this->query('level', ''),
            'levelGte' => $this->query('level_gte', ''),
            'severity' => $this->query('severity', ''),
            'search' => $this->query('search', ''),
            'agentId' => $this->query('agent_id', ''),
            'ruleId' => $this->query('rule_id', ''),
            'mitre' => $this->query('mitre', ''),
            'group' => $this->query('group', ''),
            'timeRange' => $this->query('time_range', '24h'),
            'dateFrom' => $this->query('date_from', ''),
            'dateTo' => $this->query('date_to', ''),
            'sortBy' => $this->query('sort_by', 'timestamp'),
            'sortOrder' => $this->query('sort_order', 'desc'),
            'includeSoc' => filter_var($this->query('include_soc', false), FILTER_VALIDATE_BOOLEAN),
            'alertView' => $this->query('alert_view', 'incident'),
        ];
    }
}
