<?php

namespace App\Services;

use App\Models\GamesKey;
use App\Models\LogsRoundsFree;
use Illuminate\Support\Facades\Http;

class PlayFiverService
{
    protected static $secretPlayFiver;
    protected static $codePlayFiver;
    protected static $tokenPlayFiver;

    private static function credencialFiverPlay()
    {
        $setting = GamesKey::first();
        self::$secretPlayFiver = $setting->getAttributes()['playfiver_secret'];
        self::$codePlayFiver = $setting->getAttributes()['playfiver_code'];
        self::$tokenPlayFiver = $setting->getAttributes()['playfiver_token'];
    }
    public static function RoundsFree($dados){
        self::credencialFiverPlay();
        $launchGame = self::gameLaunchFalse($dados);
        if($launchGame){
            $postArray = [
                "agent_token" => self::$tokenPlayFiver,
                "secret_key" => self::$secretPlayFiver,
                "user_code" => $dados['username'],
                "game_code" => $dados['game_code'],
                "rounds" => $dados['rounds']
            ];  
            $response = Http::withOptions([
                'curl' => [
                    CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
                ],
            ])->post("https://api.playfivers.com/api/v2/free_bonus", $postArray);
            $data = $response->json();
            LogsRoundsFree::create([
                'game_code' => $dados['game_code'],
                'username' => $dados['username'],
                'status' => $data['status'],
                'message' => $data['msg']
            ]);
            if ($response->successful() && $data['status']) {
                return ["status" => true, "message" => $data['msg']];
            } else {
                return ["status" => false, "message" => $data['msg']];
            }
            
        }
        LogsRoundsFree::create([
            'game_code' => $dados['game_code'],
            'username' => $dados['username'],
            'status' => false,
            'message' => "Não foi possivel lançar um jogo falso antes!"
        ]);
        return ["status" => false, "message" => "Não foi possivel lançar um jogo falso antes!"];

    }
    private static function gameLaunchFalse($dados){
        $postArray = [
            "agentToken" => self::$tokenPlayFiver,
            "secretKey" => self::$secretPlayFiver,
            "user_code" => $dados['username'],
            "game_code" => $dados['game_code'],
            "game_original" => false,
            "user_balance" => 100,
        ];

        $response = Http::withOptions([
            'curl' => [
                CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
            ],
        ])->post("https://api.playfivers.com/api/v2/game_launch", $postArray);

        if ($response->successful()) {
            return true;
        } else {
            return false;
        }
    }
}
