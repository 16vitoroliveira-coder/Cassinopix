<?php


use App\Http\Controllers\Gateway\OndaPayController;
use Illuminate\Support\Facades\Route;

Route::prefix('ondapay')
    ->group(function () {
        Route::post('callback', [OndaPayController::class, 'callbackMethod']);
        Route::post('payment', [OndaPayController::class, 'callbackMethodPayment']);
    });
