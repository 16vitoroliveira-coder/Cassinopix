<?php

namespace App\Http\Controllers\Api\Auth;

use App\Models\SpinRuns;
use App\Models\Setting;
use App\Models\Session;
use App\Models\Wallet;
use App\Traits\Affiliates\AffiliateHistoryTrait;
use App\Http\Controllers\Controller;
use App\Models\AffiliateHistory;
use App\Models\User;
use App\Helpers\Core as Helper;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;


class AuthController extends Controller
{
    use AffiliateHistoryTrait;

    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth.jwt', ['except' => ['login', 'register', 'submitForgetPassword', 'submitResetPassword']]);
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    public function verify()
    {
        return response()->json(auth('api')->user());
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
public function login(Request $request)
{
    try {
        // 1) tenta gerar o JWT
        $credentials = $request->only(['email','password']);
        if (! $jwtToken = auth('api')->attempt($credentials)) {
            return response()->json(['error' => trans('Check credentials')], 400);
        }

        // 2) obtém o usuário autenticado
        $user = auth('api')->user();

        // 3) invalida quaisquer sessões ainda ativas
        Session::where('user_id', $user->id)
               ->where('is_active', true)
               ->update(['is_active' => false]);

        // 4) prepara novo token de sessão
        $sessionToken = hash_hmac('sha256', Str::random(40), config('app.key'));
        $now = Carbon::now();

        // 5) captura informações do cliente
        $ip       = $request->ip();
        $agent    = $request->header('User-Agent');
        $platform = $request->header('Sec-CH-UA-Platform') ?: null;
        $isMobile = Str::contains(strtolower($agent), ['mobile','android','iphone']);
        $device   = $isMobile ? 'mobile' : 'desktop';

        // 6) cria a nova sessão no banco
        Session::create([
            'user_id'       => $user->id,
            'token'         => $sessionToken,
            'last_activity' => $now,
            'expires_at'    => $now->copy()->addDays(5),
            'is_active'     => true,
            // campos adicionais
            'ip_address'    => $ip,
            'user_agent'    => $agent,
            'platform'      => $platform,
            'device'        => $device,
        ]);

        // 7) retorna o JWT e o token de sessão
        return $this->respondWithToken($jwtToken, $sessionToken);

    } catch (JWTException $e) {
        return response()->json(['error' => 'Could not create token'], 400);
    }
}

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        try {
            $setting = Helper::getSetting();

            // Regras de validação
            $validator = Validator::make($request->all(), [
                'name'           => 'required|string|max:255',
                'email'          => 'required|email|unique:users|max:255',
                'phone'          => 'required|string|min:10|max:15',
                'password'       => ['required', Rules\Password::min(6)],
                'cupom'          => 'nullable|string',
                'reference_code' => 'nullable|string',
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors(), 400);
            }

            // Validação do cupom
            if (! empty($request->cupom)) {
                $cupom = \App\Models\Cupom::where('codigo', $request->cupom)->first();
                if (! $cupom) {
                    return response()->json(['error' => 'Esse cupom não existe'], 400);
                }
                if ($cupom->validade < now()) {
                    return response()->json(['error' => 'Esse cupom já está expirado'], 400);
                }
                if ($cupom->usos >= $cupom->quantidade_uso) {
                    return response()->json([
                        'error' => 'Vários usuários resgataram esse cupom hoje, tente novamente amanhã ou outro cupom'
                    ], 400);
                }
            }

            // Prepara dados do usuário
            $userData = $request->only(['name','email','phone']);
            $userData['password']           = $request->password;
            $userData['affiliate_cpa']      = $setting->cpa_value;
            $userData['affiliate_baseline'] = $setting->cpa_baseline;

            // Cria usuário
            $user = User::create($userData);

            // Salva histórico de afiliado
            if (! empty($request->reference_code)) {
                $ref = User::where('inviter_code', $request->reference_code)->first();
                if ($ref) {
                    $user->update(['inviter' => $ref->id]);
                    $this->saveAffiliateHistory($user);
                }
            }

            // Cria carteira
            $this->createWallet($user);

            // Aplica bônus do cupom
            if (! empty($request->cupom)) {
                $bonus         = $cupom->valor_bonus;
                $rollover      = $bonus * $setting->rollover;
                Wallet::where('user_id', $user->id)
                    ->increment('balance_bonus', $bonus);
                Wallet::where('user_id', $user->id)
                    ->increment('balance_bonus_rollover', $rollover);
                $cupom->increment('usos');
            }

            // Autentica e gera JWT
            $token = auth('api')->attempt($request->only('email','password'));
            if (! $token) {
                return response()->json(['error' => 'Faça login ou cadastre-se para continuar'], 401);
            }

            // Cria sessão customizada (50 minutos)
            $sessionToken = hash_hmac(
                'sha256',
                Str::random(40),
                config('app.key')
            );
            $now = Carbon::now();
            Session::create([
                'user_id'       => $user->id,
                'token'         => $sessionToken,
                'last_activity' => $now,
                'expires_at'    => $now->copy()->addDays(5),
                'is_active'     => true,
            ]);

            // Retorna JWT + Session Token
            return $this->respondWithToken($token, $sessionToken);

        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 400);
        }

        return response()->json(['error' => 'User registration failed'], 400);
    }

    
    
    
    

    /**
     * @param $user
     * @return void
     */
    private function createWallet($user)
    {
        $setting = Helper::getSetting();

        Wallet::create([
            'user_id'   => $user->id,
            'currency'  => $setting->currency_code,
            'symbol'    => $setting->prefix,
            'active'    => 1
        ]);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth('api')->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        // pega o usuário logado via JWT
        $user = auth('api')->user();

        // invalida o JWT
        auth('api')->logout();

        // encerra TODAS as sessões ativas desse usuário
        Session::where('user_id', $user->id)
            ->where('is_active', true)
            ->update(['is_active' => false]);

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Heartbeat: renova a sessão atual e fecha a mais antiga se houver
     * retorna status 1 (ok) ou 0 (sessão inválida)
     */
    public function ping(Request $request)
    {
        // obtém o token de sessão
        $token = $request->header('X-Session-Token')
               ?? $request->input('session_token');

        // busca a sessão atual
        $session = Session::where('token', $token)->first();

        if (! $session || ! $session->is_active) {
            // sessão não existe ou foi inativada
            return response()->json(['status' => 0]);
        }

        // renova heartbeat: last_activity e expires_at +30m
        $session->update([
            'last_activity' => Carbon::now(),
            'expires_at'    =>  Carbon::now()->addDays(5),
        ]);

        // fecha a sessão mais antiga, se ainda houver >1 ativas
        $active = Session::where('user_id', $session->user_id)
                         ->where('is_active', true)
                         ->orderBy('created_at', 'asc')
                         ->get();

        if ($active->count() > 1) {
            // identifica a mais antiga
            $oldest = $active->first();
            // se a atual for a mais antiga, pula para a próxima
            if ($oldest->token === $token) {
                $oldest = $active->slice(1, 1)->first();
            }
            // inativa apenas essa
            $oldest->update(['is_active' => false]);
        }

        // retorna ok e reconfirma o token
        return response()->json([
            'status'        => 1,
            'session_token' => $session->token,
        ]);
    }

    /**
     * Logout da sessão atual: invalida o JWT
     */
    public function logoutSession(Request $request)
    {
        auth('api')->logout();

        return response()->json([
            'message' => 'Você está conectado em outro dispositivo'
        ], 200);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth('api')->refresh());
    }
    private function generateAffiliateCode()
    {
        do {
            $code = \Helper::generateCode(8); // Gerar código de 8 caracteres
            $checkCode = User::where('inviter_code', $code)->first();
        } while ($checkCode);

        return $code;
    }
    public function submitForgetPassword(Request $request)
    {
        $request->validate(['email' => 'required|email']);

        $user = DB::table('users')->where('email', $request->email)->first();
        if (!$user) {
            return response()->json(['status' => false, 'message' => 'Email not found.'], 404);
        }

        $token = Str::random(60);
        $expiresAt = Carbon::now()->addMinutes(5);

        DB::transaction(function () use ($request, $token, $expiresAt) {
            DB::table('password_reset_tokens')->where('email', $request->email)->delete();
            DB::table('password_reset_tokens')->insert([
                'email' => $request->email,
                'token' => $token,
                'created_at' => Carbon::now(),
                'expires_at' => $expiresAt
            ]);

            Mail::send('emails.forget-password', ['token' => $token, 'resetLink' => url('/reset-password/' . $token)], function ($message) use ($request) {
                $message->to($request->email)->subject('Reset Password');
            });
        });

        return response()->json(['status' => true, 'message' => 'We have emailed your password reset link!'], 200);
    }

    public function submitResetPassword(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
            'token' => 'required',
            'password' => 'required|string|min:6|confirmed'
        ]);

        $tokenData = DB::table('password_reset_tokens')
                       ->where('token', $request->token)
                       ->where('expires_at', '>', Carbon::now())
                       ->first();

        if (!$tokenData || $tokenData->email !== $request->email) {
            return response()->json(['error' => 'Invalid or expired token.'], 400);
        }

        $user = User::where('email', $request->email)->firstOrFail();
        $user->password = Hash::make($request->password);
        $user->save();
        DB::table('password_reset_tokens')->where('email', $request->email)->delete();

        return response()->json(['status' => true, 'message' => 'Your password has been changed!'], 200);
    }

    protected function respondWithToken(string $jwtToken, string $sessionToken)
    {
        return response()->json([
            'access_token'       => $jwtToken,
            'token_type'         => 'bearer',
            'expires_in'         => auth('api')->factory()->getTTL() * 60,
            'session_token'      => $sessionToken,
            'session_expires_in' => 30 * 60,           // 30 minutos em segundos
            'user'               => auth('api')->user(),
        ]);
    }
}
