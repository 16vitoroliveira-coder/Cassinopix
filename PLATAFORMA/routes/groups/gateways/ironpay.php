<?php

use App\Http\Controllers\Gateway\IronPayController;
use Illuminate\Support\Facades\Route;

Route::prefix('ironpay')
    ->group(function () {
        Route::any('callback', [IronPayController::class, 'callbackMethod']);
    });
