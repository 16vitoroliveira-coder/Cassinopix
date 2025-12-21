<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class LogsRoundsFree extends Model
{
    use HasFactory;
    protected $table = 'logs_rounds_free';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'game_code',
        'username',
        'status',
        'message'
    ];
}
