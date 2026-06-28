<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreUserRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        // Cek apakah user yang sedang login memiliki role 'Admin'
        return $this->user() && $this->user()->role === 'Admin';
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array|string>
     */
    public function rules(): array
    {
        return [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users,email',
            'password' => 'required|string|min:8', // Tambahkan 'confirmed' jika ada input password_confirmation
            'role' => 'nullable|string|in:Admin,SOC Analyst', // Sesuaikan dengan daftar role Anda
            'department' => 'nullable|string|max:255',
            'phone' => 'nullable|string|max:20',
            'status' => 'nullable|string|in:active,inactive',
        ];
    }

    /**
     * Custom pesan error (opsional)
     */
    public function messages(): array
    {
        return [
            'email.unique' => 'Email ini sudah terdaftar.',
        ];
    }
}
