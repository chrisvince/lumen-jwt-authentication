<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\User;
use Illuminate\Auth\Passwords\PasswordBrokerManager;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct() {
        $this->middleware('auth', [
            'only' => [
                'user',
                'logout',
                'deactivate',
                'verifyEmailRequest'
            ]
        ]);
    }
    
    /**
     * Create a new user.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request) {
        $this->validate($request, [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);
        $user = User::create([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => Hash::make($request->input('password'), [])
        ]);
        $user->sendEmailVerificationNotification();
        $credentials = $request->only(['email', 'password']);
        return $this->loginWithCredendials($credentials);
    }
    
    /**
     * Deactivate a user.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function deactivate(Request $request) {
        Auth::invalidate();
        Auth::user()->delete();
        return response()->json(['message' => 'User has been deactivated']);
    }
    
    /**
     * Restore a user.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function restore(Request $request) {
        $this->validate($request, [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:6'
        ]);
        $user = User::withTrashed()->where('email', $request->email)->first();
        if(!$user) {
            return response()->json(['error' => 'User does not exist'], 400);
        }
        if (!$user->trashed()) {
            return response()->json(['error' => 'User is already active'], 400);
        }
        if(!Hash::check($request->password, $user->password)) {
            return response()->json(['error' => 'Unauthenticated'], 401);
        }
        $user->restore();
        $credentials = $request->only(['email', 'password']);
        return $this->loginWithCredendials($credentials);
    }
    
    /**
     * Login a user.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request) {
        $this->validate($request, [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:6'
        ]);
        $user = User::withTrashed()->where('email', $request->email)->first();
        if($user->trashed()) {
            return response()->json(['error' => 'User has been deactivated'], 401 );
        }
        $credentials = $request->only(['email', 'password']);
        return $this->loginWithCredendials($credentials);
    }
    
    /**
     * Get the authenticated user.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function user() {
        try {
            $user = Auth::user();
        } catch (\Tymon\JWTAuth\Exceptions\UnauthorizedHttpException $e) {
            return response()->json(['error' => 'Token not provided'], 401); 
        }
        return response()->json($user);
    }
    
    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout() {
        Auth::logout();
        return response()->json(['message' => 'The user has been logged out']);
    }
    
    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh() {
        try {
            $token = Auth::refresh();
        } catch (\Tymon\JWTAuth\Exceptions\TokenBlacklistedException $e) {
            return response()->json(['error' => 'The token has been blacklisted'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Unauthenticated'], 401);
        }
        return $this->respondWithToken($token);
    }
    
    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token) {
        return response()->json([
            'access_token' => $token,
            // 'token_type' => 'bearer',
            // 'expires_in' => Auth::factory()->getTTL() * 60
        ]);
    }
    
    /**
     * Login with and return JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function loginWithCredendials($credentials) {
        if (!$token = Auth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->respondWithToken($token);
    }
    
    /**
     * Request a password reset email.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function resetPasswordRequest(Request $request) {
        $this->validate($request, [
            'email' => 'required|email'
        ]);
        $user = User::withTrashed()->where('email', $request->email)->first();
        if(!$user) {
            return response()->json(['error' => 'User does not exist'], 400);
        }
        $response = $this->broker()->sendResetLink($request->only('email'));
        if($response !== Password::RESET_LINK_SENT) {
            return response()->json(['error' => 'There was an error sending password reset email'], 400);
        }
        return response()->json(['message' => 'Password reset email has been sent']);
    }
    
    /**
     * Reset a password with a valid password reset token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function resetPassword(Request $request) {
        $this->validate($request, [
            'token'    => 'required',
            'email' => 'required|string|email|max:255',
            'password' => 'required|confirmed|min:6',
        ]);
        $response = $this->broker()->reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user, $password) {
                $user->password = Hash::make($password);
                $user->save();
            }
        );
        if($response !== Password::PASSWORD_RESET) {
            return response()->json(['error' => 'There was an error resetting the password'], 400);
        }
        return response()->json(['message' => 'Password has been reset']);
    }
    
    /**
     * Get the broker to be used during password reset.
     *
     * @return \Illuminate\Contracts\Auth\PasswordBroker
     */
    public function broker() {
        $passwordBrokerManager = new PasswordBrokerManager(app());
        return $passwordBrokerManager->broker();
    }
    
    /**
     * Request email verification.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function requestEmailVerification() {
        try {
            $user = Auth::user();
        } catch (\Tymon\JWTAuth\Exceptions\UnauthorizedHttpException $e) {
            return response()->json(['error' => 'Token not provided'], 401); 
        }
        $user->sendEmailVerificationNotification();
        return response()->json(['message' => 'Email verification email has been sent']);
    }
    
    /**
     * Verify email address.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function verifyEmail(Request $request) {
        $this->validate($request, [
            'email' => 'required|string|email|max:255',
            'token' => 'required|string',
        ]);
        $user = User::where('email', $request->email)->first();
        return $user->markEmailAsVerified($request->token);
    }
    
    /**
     * Check if an email address has been verified.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function checkEmailVerification(Request $request) {
        try {
            $user = Auth::user();
        } catch (\Tymon\JWTAuth\Exceptions\UnauthorizedHttpException $e) {
            return response()->json(['error' => 'Token not provided'], 401); 
        }
        if(!$user->hasVerifiedEmail()) {
            return response()->json(['message' => 'Email has not been verified']);
        }
        $user->sendEmailVerificationNotification();
        return response()->json(['message' => 'Email has been verified']);
    }
}
