<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ConfigRoundsFree extends Model
{
    use HasFactory;
    protected $table = 'configs_rounds_free';


    protected $fillable = [
        'spins',
        'game_code',
        'value',
    ];

    protected $casts = [
        'value' => 'decimal:2',
    ];

    public function game()
    {
        return $this->belongsTo(Game::class, 'game_code', 'game_code');
    }
}
