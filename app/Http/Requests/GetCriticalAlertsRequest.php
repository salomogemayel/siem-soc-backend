<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class GetCriticalAlertsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'level' => ['nullable', 'integer', 'min:1', 'max:15'],
            'size' => ['nullable', 'integer', 'min:1', 'max:100'],
        ];
    }

    public function filters(): array
    {
        $validated = $this->validated();

        return [
            'level' => (int) ($validated['level'] ?? 10),
            'size' => (int) ($validated['size'] ?? 20),
        ];
    }
}
