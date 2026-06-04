<?php

namespace App\Http\Controllers;

use App\Models\UnusualIpAlert;
use Illuminate\Http\Request;

class UnusualIpAlertController extends Controller
{
    public function index(Request $request)
    {
        $size = (int) $request->query('size', 20);
        $status = $request->query('status');
        $search = $request->query('search');

        $query = UnusualIpAlert::query()
            ->orderByDesc('detected_at')
            ->orderByDesc('created_at');

        if ($status) {
            $query->where('status', $status);
        }

        if ($search) {
            $query->where(function ($q) use ($search) {
                $q->where('cis_user_id', 'like', "%{$search}%")
                    ->orWhere('ip_address', 'like', "%{$search}%")
                    ->orWhere('wazuh_alert_id', 'like', "%{$search}%")
                    ->orWhere('reason', 'like', "%{$search}%");
            });
        }

        $alerts = $query->paginate($size);

        return response()->json([
            'success' => true,
            'data' => $alerts->items(),
            'total' => $alerts->total(),
            'page' => $alerts->currentPage(),
            'size' => $alerts->perPage(),
            'total_pages' => $alerts->lastPage(),
        ]);
    }

    public function updateStatus(Request $request, $id)
    {
        $validated = $request->validate([
            'status' => 'required|in:new,reviewed,false_positive',
        ]);

        $alert = UnusualIpAlert::findOrFail($id);

        $alert->update([
            'status' => $validated['status'],
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Unusual IP alert status updated successfully',
            'data' => $alert,
        ]);
    }
}
