<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

class Session extends Model
{
    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'sessions';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'user_id',
        'token',
        'last_activity',
        'expires_at',
        'is_active',
        // → adiciona estas 4 linhas:
        'ip_address',
        'user_agent',
        'platform',
        'device',
    ];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'last_activity' => 'datetime',
        'expires_at'    => 'datetime',
        'is_active'     => 'boolean',
    ];

    /**
     * Indicates if the model should be timestamped.
     *
     * @var bool
     */
    public $timestamps = true;

    /**
     * Get the user that owns the session.
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Determine if the session is expired or inactive.
     *
     * @return bool
     */
    public function isExpired()
    {
        return ! $this->is_active || $this->expires_at->lt(Carbon::now());
    }
}
