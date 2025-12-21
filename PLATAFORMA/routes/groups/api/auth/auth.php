<?php

use App\Http\Controllers\Api\Auth\AuthController;
use Illuminate\Support\Facades\Route;

Route::group(['middleware' => 'api'], function () {

    Route::post('login', [AuthController::class, 'login']);
    Route::post('register', [AuthController::class, 'register']);

    Route::post('forget-password', [AuthController::class, 'submitForgetPassword']);
    Route::post('reset-password/{token}', [AuthController::class, 'submitResetPassword']);

    Route::group(['middleware' => ['auth.jwt']], function () {
        Route::get('verify', [AuthController::class, 'verify']); // verifica se está autenticado
        Route::post('refresh', [AuthController::class, 'refresh']);
        Route::post('logout', [AuthController::class, 'logout']);
        // Heartbeat que renova a sessão atual, fecha a mais antiga e devolve status (0 ou 1)
        Route::post('session/ping', [AuthController::class, 'ping']);
        // Logout da sessão atual (queima o JWT) quando status===0 no ping
        Route::post('session/logout_session', [AuthController::class, 'logoutSession']);
        Route::post('me', [AuthController::class, 'me']);
    });
});
