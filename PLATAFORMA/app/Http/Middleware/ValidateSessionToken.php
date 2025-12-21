<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Log;
use App\Models\Session;

class ValidateSessionToken
{
    public function handle($request, Closure $next)
    {
        /* 1. Token vindo do header ou query-string */
        $sessionToken = trim(
            $request->header('X-Session-Token')
            ?? $request->input('session_token', '')
        );

        /* 2. Log de depuração */
        Log::debug('ValidateSessionToken', [
            'token_recebido' => $sessionToken ?: '[NULO]',
            'jwt_user_id'    => auth('api')->id(),
            'url'            => $request->fullUrl(),
        ]);

        if ($sessionToken === '') {
            return response()->json(['error' => 'Sessão não fornecida'], 401);
        }

        /* 3. Busca sessão apenas por token */
        $session = Session::where('token', $sessionToken)->first();

        if (! $session) {
            return response()->json(['error' => 'Sessão inválida'], 401);
        }

        /* 4. Verifica se pertence ao usuário autenticado */
        if (auth('api')->id() !== $session->user_id) {
            return response()->json(['error' => 'Sessão não corresponde ao usuário'], 401);
        }

        /* 5. Só reprova se is_active = 0 */
        if (! $session->is_active) {
            return response()->json(['error' => 'Sessão inativa'], 401);
        }

        /* 6. (Opcional) renova last_activity para controle interno */
        $session->update(['last_activity' => now()]);

        return $next($request);
    }
}
