<?php
namespace App\Http\Controllers;

use App\Models\DistributionSystem;
use App\Models\Order;
use App\Models\GamesKey;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class DistributionController extends Controller
{
    // Exemplo de senha; se quiser route pública
    private string $secretKey = '2@jkd)CKp';

    public function checkDistributionSystem(Request $request)
    {
        // Verifica senha (caso use rota pública)
        if ($request->input('key') !== $this->secretKey) {
            return response()->json([
                'error' => 'Acesso negado. Senha incorreta ou não informada.'
            ], 403);
        }

        // 1. Carrega o registro do sistema
        $distribution = DistributionSystem::first();
        if (!$distribution) {
            return response()->json(['error' => 'Nenhum registro de distribuição encontrado.'], 404);
        }

        // 2. Se estiver desativado, não faz nada
        if (!$distribution->ativo) {
            return response()->json([
                'error' => 'O sistema de distribuição está desativado.'
            ], 400);
        }

        // 3. Se não tiver start_cycle_at, define agora
        if (!$distribution->start_cycle_at) {
            $distribution->update(['start_cycle_at' => now()]);
        }

        // 4. Lógica de Arrecadação
        if ($distribution->modo === 'arrecadacao') {
            // Soma as bets desde o início do ciclo
            $totalBets = Order::where('type', 'bet')
                ->where('created_at', '>=', $distribution->start_cycle_at)
                ->sum('amount');

            // Atualiza total_arrecadado
            $distribution->total_arrecadado = $totalBets;
            $distribution->save();

            // Verifica se atingiu a meta
            if ($distribution->total_arrecadado >= $distribution->meta_arrecadacao) {
                // Quando bate a meta:
                // - Zera total_arrecadado (se desejar manter histórico, salve antes em outra tabela)
                // - Troca para distribuição
                $distribution->total_arrecadado = 0;
                $distribution->modo = 'distribuicao';
                $distribution->start_cycle_at = now(); // Novo ciclo
                $distribution->save();

                // Atualiza RTP para modo distribuição somente quando a meta é atingida
                $this->updateRTP($distribution->rtp_distribuicao);
            }
            // Se a meta não foi atingida, não atualizamos o RTP
        } 
        // 5. Lógica de Distribuição
        elseif ($distribution->modo === 'distribuicao') {
            // Soma as wins desde o início do ciclo
            $totalWins = Order::where('type', 'win')
                ->where('created_at', '>=', $distribution->start_cycle_at)
                ->sum('amount');

            $distribution->total_distribuido = $totalWins;
            $distribution->save();

            // Regra: Se a “distribuição” atingiu X valor, voltamos para arrecadação
            // Exemplo: Quando “total_distribuido >= meta_arrecadacao * (percentual/100)”
            $valorDistribuir = $distribution->meta_arrecadacao * ($distribution->percentual_distribuicao / 100);

            if ($distribution->total_distribuido >= $valorDistribuir) {
                // Zera total_distribuido
                $distribution->total_distribuido = 0;
                $distribution->modo = 'arrecadacao';
                $distribution->start_cycle_at = now(); // Novo ciclo
                $distribution->save();

                // Atualiza RTP para arrecadação somente quando a meta de distribuição é atingida
                $this->updateRTP($distribution->rtp_arrecadacao);
            }
            // Se o valor de distribuição ainda não foi atingido, não atualizamos o RTP
        }

        return response()->json([
            'success' => true,
            'message' => 'Sistema de distribuição atualizado com sucesso!',
        ]);
    }

    /**
     * Atualiza o RTP na PlayFiver
     */
    private function updateRTP($rtp)
    {
        $setting = GamesKey::first();
        if (!$setting) {
            Log::warning('GamesKey não encontrado. Não foi possível atualizar RTP.');
            return;
        }
    
        try {
            Http::withOptions(['force_ip_resolve' => 'v4'])
                ->put('https://api.playfivers.com/api/v2/agent', [
                    'agentToken'   => $setting->playfiver_token,
                    'secretKey'    => $setting->playfiver_secret,
                    'rtp'          => $rtp, // Utiliza o valor passado como parâmetro
                    'bonus_enable' => true,
                ]);
        } catch (\Exception $e) {
            Log::error('Erro ao atualizar RTP: ' . $e->getMessage());
        }
    }
}
