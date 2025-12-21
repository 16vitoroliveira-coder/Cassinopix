<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class OndaPay extends Model
{
    use HasFactory;
    protected $table = 'onda_pay';

    protected $fillable = [
        'user_id',
        'withdrawal_id',
        'amount',
        'status'
    ];
}
