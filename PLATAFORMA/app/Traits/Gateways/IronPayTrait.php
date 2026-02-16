<?php

namespace App\Traits\Gateways;

use App\Helpers\Core;
use App\Models\AffiliateHistory;
use App\Models\AffiliateLogs;
use App\Models\Deposit;
use App\Models\Gateway;
use App\Models\Setting;
use App\Models\Transaction;
use App\Models\User;
use App\Models\Wallet;
use App\Notifications\NewDepositNotification;
use Exception;
use App\Helpers\Core as Helper;
use App\Models\ConfigRoundsFree;
use App\Services\PlayFiverService;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

trait IronPayTrait
{
    protected static string $ironpayToken;
    protected static string $ironpayOfferHash;
    protected static string $ironpayProductHash;

    /**
     * Gera as credenciais da IronPay a partir da tabela gateways
     */
    private static function generateCredentialsIronPay()
    {
        $setting = Gateway::first();
        if (!empty($setting)) {
            self::$ironpayToken       = $setting->getAttributes()['ironpay_token'] ?? '';
            self::$ironpayOfferHash   = $setting->getAttributes()['ironpay_offer_hash'] ?? '';
            self::$ironpayProductHash = $setting->getAttributes()['ironpay_product_hash'] ?? '';
        }
    }

    /**
     * Cria uma transação PIX na IronPay e retorna o QR Code
     */
    public function requestQrcodeIronPay($request)
    {
        try {
            $setting = Core::getSetting();
            $rules = [
                'amount' => ['required', 'numeric', 'min:' . $setting->min_deposit, 'max:' . $setting->max_deposit],
                'cpf'    => ['required', 'string', 'max:255'],
            ];

            $validator = Validator::make($request->all(), $rules);
            if ($validator->fails()) {
                return response()->json($validator->errors(), 400);
            }

            self::generateCredentialsIronPay();

            $user = auth('api')->user();
            $idUnico = uniqid();
            $amountInCents = intval(floatval($request->input('amount')) * 100);

            $response = Http::withOptions([
                'force_ip_resolve' => 'v4',
            ])->post('https://api.ironpayapp.com.br/api/public/v1/transactions?api_token=' . self::$ironpayToken, [
                'amount'         => $amountInCents,
                'offer_hash'     => self::$ironpayOfferHash,
                'payment_method' => 'pix',
                'customer'       => [
                    'name'         => $user->name,
                    'email'        => $user->email,
                    'phone_number' => '00000000000',
                    'document'     => Helper::soNumero($request->cpf),
                ],
                'cart' => [
                    [
                        'product_hash'   => self::$ironpayProductHash,
                        'title'          => 'Depósito PIX',
                        'cover'          => null,
                        'price'          => $amountInCents,
                        'quantity'       => 1,
                        'operation_type' => 1,
                        'tangible'       => false,
                    ]
                ],
                'installments'       => 1,
                'expire_in_days'     => 1,
                'transaction_origin' => 'api',
                'postback_url'       => url('/ironpay/callback'),
            ]);

            if ($response->successful()) {
                $responseData = $response->json();

                $transactionHash = $responseData['hash'] ?? ($responseData['id'] ?? uniqid('iron_'));
                $pixQrCode = '';

                if (isset($responseData['pix']) && isset($responseData['pix']['pix_qr_code'])) {
                    $pixQrCode = $responseData['pix']['pix_qr_code'];
                }

                self::generateTransactionIronPay($transactionHash, floatval($request->input('amount')), $idUnico);
                self::generateDepositIronPay($transactionHash, floatval($request->input('amount')));

                return response()->json([
                    'status'        => true,
                    'idTransaction' => $transactionHash,
                    'qrcode'        => $pixQrCode,
                ]);
            }

            Log::error('IronPay: Erro ao criar transação', ['response' => $response->body()]);
            return response()->json(['error' => 'Ocorreu uma falha ao entrar em contato com o banco.'], 500);

        } catch (Exception $e) {
            Log::error('IronPay: Exception', ['message' => $e->getMessage()]);
            return response()->json(['error' => 'Erro interno'], 500);
        }
    }

    /**
     * Webhook/Callback da IronPay - chamado quando o pagamento é confirmado
     */
    public function webhookIronPay($request)
    {
        try {
            $status          = $request->input('status');
            $transactionHash = $request->input('transaction_hash');
            $amount          = $request->input('amount');

            Log::info('IronPay Webhook recebido', [
                'status'           => $status,
                'transaction_hash' => $transactionHash,
                'amount'           => $amount,
                'payload'          => $request->all(),
            ]);

            if ($status === 'paid') {
                if (self::finalizePaymentIronPay($transactionHash)) {
                    return response()->json(['success' => true], 200);
                }
            }

            return response()->json(['success' => false], 200);

        } catch (Exception $e) {
            Log::error('IronPay Webhook Error', ['message' => $e->getMessage()]);
            return response()->json(['error' => 'Erro interno'], 500);
        }
    }

    /**
     * Finaliza o pagamento: credita o saldo do usuário
     */
    private static function finalizePaymentIronPay($transactionHash): bool
    {
        $transaction = Transaction::where('payment_id', $transactionHash)
            ->where('status', 0)
            ->first();

        if (empty($transaction)) {
            Log::warning('IronPay: Transação não encontrada ou já paga', ['hash' => $transactionHash]);
            return false;
        }

        $user   = User::find($transaction->user_id);
        $wallet = Wallet::where('user_id', $transaction->user_id)->first();

        if (empty($wallet)) {
            return false;
        }

        $setting = Setting::first();

        // Verifica se é o primeiro depósito
        $checkTransactions = Transaction::where('user_id', $transaction->user_id)
            ->where('status', 1)
            ->count();

        if ($checkTransactions == 0 || empty($checkTransactions)) {
            $bonus = Helper::porcentagem_xn($setting->initial_bonus, $transaction->price);
            $wallet->increment('balance_bonus', $bonus);
            $wallet->update(['balance_bonus_rollover' => $bonus * $setting->rollover]);
        }

        // Rounds Free
        $configRounds = ConfigRoundsFree::orderBy('value', 'asc')->get();
        foreach ($configRounds as $value) {
            if ($transaction->price >= $value->value) {
                $dados = [
                    "username"  => $user->email,
                    "game_code" => $value->game_code,
                    "rounds"    => $value->spins,
                ];
                PlayFiverService::RoundsFree($dados);
                break;
            }
        }

        // Rollover depósito
        $wallet->update(['balance_deposit_rollover' => $transaction->price * intval($setting->rollover_deposit)]);

        if ($wallet->increment('balance', $transaction->price)) {
            if ($transaction->update(['status' => 1])) {
                $deposit = Deposit::where('payment_id', $transactionHash)->where('status', 0)->first();
                if (!empty($deposit)) {

                    // CPA de afiliado
                    $affHistoryCPA = AffiliateHistory::where('user_id', $user->id)
                        ->where('commission_type', 'cpa')
                        ->where('status', 0)
                        ->first();

                    if (!empty($affHistoryCPA)) {
                        $sponsorCpa = User::find($user->inviter);
                        if (!empty($sponsorCpa)) {
                            $deposited_amount = $transaction->price;
                            if ($affHistoryCPA->deposited_amount >= $sponsorCpa->affiliate_baseline || $deposit->amount >= $sponsorCpa->affiliate_baseline) {
                                $walletCpa = Wallet::where('user_id', $affHistoryCPA->inviter)->first();
                                if (!empty($walletCpa)) {
                                    $walletCpa->increment('refer_rewards', $sponsorCpa->affiliate_cpa);
                                    $affHistoryCPA->update([
                                        'status'          => 1,
                                        'deposited'       => $deposited_amount,
                                        'commission_paid' => $sponsorCpa->affiliate_cpa,
                                    ]);
                                    AffiliateLogs::create([
                                        'user_id'         => $sponsorCpa->id,
                                        'commission'      => $sponsorCpa->affiliate_cpa,
                                        'commission_type' => 'cpa',
                                        'type'            => 'increment',
                                    ]);
                                }
                            } else {
                                $affHistoryCPA->update(['deposited_amount' => $transaction->price]);
                            }
                        }
                    }

                    if ($deposit->update(['status' => 1])) {
                        $admins = User::where('role_id', 0)->get();
                        foreach ($admins as $admin) {
                            $admin->notify(new NewDepositNotification($user->name, $transaction->price));
                        }
                        return true;
                    }
                    return false;
                }
                return false;
            }
        }
        return false;
    }

    /**
     * Gera o registro de depósito
     */
    private static function generateDepositIronPay($idTransaction, $amount)
    {
        $userId = auth('api')->user()->id;
        $wallet = Wallet::where('user_id', $userId)->first();

        Deposit::create([
            'payment_id' => $idTransaction,
            'user_id'    => $userId,
            'amount'     => $amount,
            'type'       => 'pix',
            'currency'   => $wallet->currency,
            'symbol'     => $wallet->symbol,
            'status'     => 0,
        ]);
    }

    /**
     * Gera o registro de transação
     */
    private static function generateTransactionIronPay($idTransaction, $amount, $idUnico)
    {
        $setting = Core::getSetting();

        Transaction::create([
            'payment_id'     => $idTransaction,
            'user_id'        => auth('api')->user()->id,
            'payment_method' => 'pix',
            'price'          => $amount,
            'currency'       => $setting->currency_code,
            'status'         => 0,
            'idUnico'        => $idUnico,
        ]);
    }
}
