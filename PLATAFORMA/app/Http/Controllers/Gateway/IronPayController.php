<?php

namespace App\Http\Controllers\Gateway;

use App\Http\Controllers\Controller;
use App\Traits\Gateways\IronPayTrait;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class IronPayController extends Controller
{
    use IronPayTrait;

    /**
     * Callback/Webhook da IronPay - recebe notificação de pagamento
     */
    public function callbackMethod(Request $request)
    {
        Log::info('IronPay Callback recebido', ['data' => $request->all()]);
        return self::webhookIronPay($request);
    }

    /**
     * Gera QR Code PIX via IronPay
     */
    public function getQRCodePix(Request $request)
    {
        return self::requestQrcodeIronPay($request);
    }
}
