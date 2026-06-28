<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\SocNotificationController;
use App\Http\Controllers\UnusualIpAlertController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\WazuhController;
use App\Http\Controllers\WazuhRuleController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('/login', [AuthController::class, 'login']);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);

    Route::get('/user', function (Request $request) {
        return $request->user();
    });

    Route::get('/profile', [ProfileController::class, 'show']);
    Route::put('/profile', [ProfileController::class, 'update']);
    Route::put('/profile/password', [ProfileController::class, 'changePassword']);

    Route::prefix('admin')->group(function () {
        Route::get('/users', [UserController::class, 'index']); // Tambahkan baris ini
        Route::post('/users', [UserController::class, 'store']);
    });

    Route::prefix('wazuh')->group(function () {
        Route::get('/logs', [WazuhController::class, 'logs']);
        Route::get('/logs/filters', [WazuhController::class, 'logFilters']);

        Route::get('/alerts', [WazuhController::class, 'alerts']);
        Route::get('/alerts/{id}', [WazuhController::class, 'alertDetail']);

        Route::get('/agents', [WazuhController::class, 'agents']);

        Route::get('/rules', [WazuhController::class, 'rules']);
        Route::post('/rules', [WazuhRuleController::class, 'store']);
        Route::put('/rules/{id}', [WazuhRuleController::class, 'update']);
        Route::delete('/rules/{id}', [WazuhRuleController::class, 'destroy']);
        Route::post('/rules/reload', [WazuhRuleController::class, 'reload']);

        Route::get('/manager', [WazuhController::class, 'manager']);
    });

    Route::get('/notifications', [SocNotificationController::class, 'index']);
    Route::get('/notifications/unread-count', [SocNotificationController::class, 'unreadCount']);

    Route::put('/notifications/read-all', [SocNotificationController::class, 'markAllAsRead']);
    Route::put('/notifications/{id}/read', [SocNotificationController::class, 'markAsRead']);

    Route::get('/unusual-ip-alerts', [UnusualIpAlertController::class, 'index']);
    Route::patch('/unusual-ip-alerts/{id}/status', [UnusualIpAlertController::class, 'updateStatus']);
});
