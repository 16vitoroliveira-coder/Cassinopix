<?php

use App\Http\Controllers\Gateway\OndaPayController;
use Illuminate\Support\Facades\Route;

Route::prefix('ondapay')
    ->group(function () {
        Route::post('qrcode-pix', [OndaPayController::class, 'getQRCodePix']);
        Route::post('consult-status-transaction', [OndaPayController::class, 'consultStatusTransactionPix']);
    });
