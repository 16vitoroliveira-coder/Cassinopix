<?php

namespace App\Http\Middleware;

use Closure;
use App\Models\Session;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class ValidateSession
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): \Illuminate\Http\Response  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // 1) Fecha todas as sessões expiradas
        Session::where('is_active', true)
               ->where('expires_at', '<', Carbon::now())
               ->update(['is_active' => false]);

        // 2) Obtém o token enviado no header
        $token = $request->header('X-Session-Token');
        if (! $token) {
            return response()->json(['error' => 'Sessão não fornecida'], 401);
        }

        // 3) Busca a sessão no banco
        $session = Session::where('token', $token)->first();

        if (! $session || ! $session->is_active || $session->expires_at->lt(Carbon::now())) {
            return response()->json(['error' => 'Sessão inválida ou expirada'], 401);
        }

        // 4) Renova heartbeat: última atividade e novo expires_at (+30m)
        $session->update([
            'last_activity' => Carbon::now(),
            'expires_at'    => Carbon::now()->addDays(5),
        ]);

        // 5) Autentica o usuário para o restante da request
        Auth::loginUsingId($session->user_id);

        return $next($request);
    }
}
