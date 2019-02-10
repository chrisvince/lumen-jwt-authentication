<?php

namespace App;

use Illuminate\Auth\Authenticatable;
use Laravel\Lumen\Auth\Authorizable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Auth\Passwords\CanResetPassword as CanResetPasswordTrait;
use Illuminate\Contracts\Auth\CanResetPassword as CanResetPasswordInterface;
use Illuminate\Notifications\Notifiable;
use App\Notifications\Auth\ResetPassword;
use App\Notifications\Auth\VerifyEmail;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Support\Facades\Hash;
use Carbon\Carbon;
use DB;
use App\Scopes\User\DeactivatedScope;

class User
    extends Model
    implements
        AuthenticatableContract,
        AuthorizableContract,
        JWTSubject,
        CanResetPasswordInterface
{
    use Authenticatable,
        Authorizable,
        CanResetPasswordTrait,
        Notifiable;
        
    /**
     * The "booting" method of the model.
     *
     * @return void
     */
    protected static function boot()
    {
        parent::boot();

        static::addGlobalScope(new DeactivatedScope);
    }

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name', 'email', 'password'
    ];

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = [
        'password',
    ];
    
    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
    
    /**
     * The attributes that should be mutated to dates.
     *
     * @var array
     */
    protected $dates = ['deactivated_at'];
    
   /**
     * Send the password reset notification.
     *
     * @param  string  $token
     * @return void
     */
    public function sendPasswordResetNotification($token)
    {
        $this->notify(new ResetPassword($token));
    }
    
    /**
     * Determine if the user has verified their email address.
     *
     * @return bool
     */
    public function hasVerifiedEmail()
    {
        return ! is_null($this->email_verified_at);
    }
    /**
     * Mark the given user's email as verified.
     *
     * @return bool
     */
    public function markEmailAsVerified($token)
    {
        $userVerification = DB::table('email_verifications')->where('email', $this->email);
        $match = false;
        if($this->email_verified_at) {
            return response()->json([
                'message' => 'The email address has already been verified'
            ], 409);
        }
        if(!$userVerification->exists()) {
            return response()->json([
                'message' => 'The email address could not be verified'
            ], 404);
        }
        foreach($userVerification->get() as $verification) {
            if(!Hash::check($token, $verification->token)) {
                continue;
            }
            $match = true;
        }
        if(!$match) {
            return response()->json([
                'message' => 'The email address could not be verified'
            ], 404);
        }
        $userVerification->delete();
        $this->forceFill([
            'email_verified_at' => $this->freshTimestamp(),
        ])->save();
        return response()->json([
            'message' => 'The email address has been verified'
        ], 200);
    }
    
    /**
     * Send the email verification notification.
     *
     * @return void
     */
    public function sendEmailVerificationNotification()
    {
        if($this->email_verified_at) {
            return response()->json([
                'message' => 'The email address has been already been verified'
            ], 409);
        }
        $token = str_random(64);
        DB::table('email_verifications')->insert([
            'email' => $this->email,
            'token' => Hash::make($token),
            'created_at' => Carbon::now()
        ]);
        $this->notify(new VerifyEmail($token));
        return response()->json([
            'message' => 'An email address verification email has been sent'
        ], 200);
    }
    
    /**
     * Scope to include deactivated users.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeWithDeactivated($query) {
        $query->withoutGlobalScope(DeactivatedScope::class);
    }
    
    /**
     * Determine if the user has been deactivated.
     *
     * @return bool
     */
    public function deactivated()
    {
        return ! is_null($this->deactivated_at);
    }
    
    /**
     * Deactivate the user.
     *
     * @return bool
     */
    public function deactivate() {
        $this->deactivated_at = Carbon::now();
        return $this->save();
    }
    
    /**
     * Reactivate the user.
     *
     * @return bool
     */
    public function reactivate() {
        $this->deactivated_at = null;
        return $this->save();
    }
}
