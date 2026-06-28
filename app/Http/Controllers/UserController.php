<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Http\Requests\StoreUserRequest;
use Illuminate\Http\JsonResponse;

class UserController extends Controller
{
    /**
     * Menampilkan daftar user
     */
    public function index(): JsonResponse
    {
        // Mengambil semua data user, urutkan dari yang terbaru
        $users = User::orderBy('created_at', 'desc')->get();

        return response()->json([
            'status' => 'success',
            'data' => $users
        ]);
    }

    /**
     * Store a newly created user in storage.
     */
    public function store(StoreUserRequest $request): JsonResponse
    {
        $validated = $request->validated();

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => $validated['password'],
            'role' => $validated['role'] ?? 'SOC Analyst',
            'department' => $validated['department'] ?? null,
            'phone' => $validated['phone'] ?? null,
            // Status dihilangkan dari input, biarkan default database (misal: active)
        ]);

        return response()->json([
            'status' => 'success',
            'message' => 'User berhasil ditambahkan',
            'data' => $user
        ], 201);
    }
}
