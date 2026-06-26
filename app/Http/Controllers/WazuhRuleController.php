<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;

class WazuhRuleController extends Controller
{
    public function store(): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => 'Store rule endpoint ready',
        ]);
    }

    public function update(string $id): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => "Update rule {$id} endpoint ready",
        ]);
    }

    public function destroy(string $id): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => "Delete rule {$id} endpoint ready",
        ]);
    }

    public function reload(): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => 'Reload Wazuh endpoint ready',
        ]);
    }
}
