<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class GetWazuhLogsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    protected function prepareForValidation(): void
    {
        $this->merge([
            'agent_id' => $this->input('agent_id', $this->input('agentId')),
            'time_range' => $this->input('time_range', $this->input('timeRange', '24h')),
            'date_from' => $this->input('date_from', $this->input('dateFrom')),
            'date_to' => $this->input('date_to', $this->input('dateTo')),
        ]);
    }

    public function rules(): array
    {
        return [
            'page' => ['nullable', 'integer', 'min:1'],
            'size' => ['nullable', 'integer', 'min:1', 'max:100'],
            'search' => ['nullable', 'string', 'max:255'],
            'agent_id' => ['nullable', 'string', 'max:50'],
            'location' => ['nullable', 'string', 'max:255'],
            'decoder' => ['nullable', 'string', 'max:100'],
            'program' => ['nullable', 'string', 'max:100'],
            'time_range' => ['nullable', 'string', 'in:15m,30m,1h,6h,24h,7d,30d,custom'],
            'date_from' => ['nullable', 'required_if:time_range,custom', 'date'],
            'date_to' => ['nullable', 'required_if:time_range,custom', 'date', 'after_or_equal:date_from'],
            'log_type' => ['nullable', 'in:alert,raw'],
        ];
    }

    public function filters(): array
    {
        $validated = $this->validated();

        return [
            'page' => (int) ($validated['page'] ?? 1),
            'size' => (int) ($validated['size'] ?? 20),
            'search' => $validated['search'] ?? '',
            'agentId' => $validated['agent_id'] ?? '',
            'location' => $validated['location'] ?? '',
            'decoder' => $validated['decoder'] ?? '',
            'program' => $validated['program'] ?? '',
            'timeRange' => $validated['time_range'] ?? '24h',
            'dateFrom' => $validated['date_from'] ?? '',
            'dateTo' => $validated['date_to'] ?? '',
            'logType' => $this->query('log_type', ''),
        ];
    }
}
