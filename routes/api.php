<?php

use App\Http\Controllers\Api\SocNotificationController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\AlertController;
use App\Http\Controllers\WazuhController;
use App\Http\Controllers\UnusualIpAlertController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::post('/login', [AuthController::class, 'login']);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);

    Route::get('/user', function (Request $request) {
        return $request->user();
    });

    Route::get('/profile', [ProfileController::class, 'show']);
    Route::put('/profile', [ProfileController::class, 'update']);
    Route::put('/profile/password', [ProfileController::class, 'changePassword']);

    Route::prefix('wazuh')->group(function () {
        Route::get('/alerts', [WazuhController::class, 'alerts']);
        Route::get('/agents', [WazuhController::class, 'agents']);
        Route::get('/rules', [WazuhController::class, 'rules']);
        Route::get('/manager', [WazuhController::class, 'manager']);
        Route::get('/logs', [WazuhController::class, 'logs']);
        Route::get('/logs/filters', [WazuhController::class, 'logFilters']);
    });

    Route::get('/notifications', [SocNotificationController::class, 'index']);
    Route::get('/notifications/unread-count', [SocNotificationController::class, 'unreadCount']);
    Route::put('/notifications/{id}/read', [SocNotificationController::class, 'markAsRead']);
    Route::put('/notifications/read-all', [SocNotificationController::class, 'markAllAsRead']);

    Route::get('/unusual-ip-alerts', [UnusualIpAlertController::class, 'index']);
    Route::patch('/unusual-ip-alerts/{id}/status', [UnusualIpAlertController::class, 'updateStatus']);
});
