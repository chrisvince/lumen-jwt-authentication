<?php

namespace App\Auth\Passwords;

use Illuminate\Auth\Passwords\PasswordBroker as VendorPasswordBorker;
use App\User;

class PasswordBroker extends VendorPasswordBorker
{
    /**
     * Send a password reset link to a user.
     *
     * @param  array  $credentials
     * @return string
     */
    public function sendResetLink(array $credentials)
    {
        $user = User::withDeactivated()->where('email', $credentials['email'])->first();

        if (is_null($user)) {
            return static::INVALID_USER;
        }

        $user->sendPasswordResetNotification(
            $this->tokens->create($user)
        );

        return static::RESET_LINK_SENT;
    }
    
    /**
     * Validate a password reset for the given credentials.
     *
     * @param  array  $credentials
     * @return \Illuminate\Contracts\Auth\CanResetPassword|string
     */
    protected function validateReset(array $credentials)
    {
        if (is_null($user = User::withDeactivated()->where('email', $credentials['email'])->first())) {
            return static::INVALID_USER;
        }

        if (! $this->validateNewPassword($credentials)) {
            return static::INVALID_PASSWORD;
        }

        if (! $this->tokens->exists($user, $credentials['token'])) {
            return static::INVALID_TOKEN;
        }

        return $user;
    }
}
