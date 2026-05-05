<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AlertController;
use App\Http\Controllers\WazuhController;

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

Route::prefix('wazuh')->group(function () {
    Route::get('/agents', [WazuhController::class, 'agents']);
    Route::get('/rules', [WazuhController::class, 'rules']);
    Route::get('/manager', [WazuhController::class, 'manager']);
    Route::get('/alerts', [WazuhController::class, 'alerts']);
});
