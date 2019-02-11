<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\User;
use App\Auth\Passwords\PasswordBrokerManager;
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
                'verifyEmailRequest',
                'requestEmailVerification',
                'checkEmailVerification',
                'getUser'
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
        Auth::user()->deactivate();
        return response()->json([
            'message' => 'The user has been deactivated'
        ], 200);
    }
    
    /**
     * Reactivate a user.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function reactivate(Request $request) {
        $this->validate($request, [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:6'
        ]);
        $user = User::withDeactivated()->where('email', $request->email)->first();
        if(!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'Unauthenticated'
            ], 401);
        }
        if (!$user->deactivated()) {
            return response()->json([
                'message' => 'The user is already active'
            ], 409);
        }
        $user->reactivate();
        $credentials = $request->only(['email', 'password']);
        return $this->loginWithCredendials($credentials);
    }
    
    /**
     * Log the user in.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request) {
        $this->validate($request, [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:6'
        ]);
        $user = User::withDeactivated()->where('email', $request->email)->first();
        if(!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'Unauthenticated'
            ], 401);
        }
        if($user->deactivated()) {
            return response()->json([
                'message' => 'The user is deactivated'
            ], 401 );
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
        $user = $this->getUser();
        return response()->json($user);
    }
    
    /**
     * Log the user out.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout() {
        Auth::logout();
        return response()->json([
            'message' => 'The user has been logged out'
        ], 200);
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
            return response()->json([
                'message' => 'Session expired'
            ], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json([
                'message' => 'Unauthenticated'
            ], 401);
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
            'access_token' => $token
        ]);
    }
    
    /**
     * Login with and return JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function loginWithCredendials($credentials) {
        if (!$token = Auth::attempt($credentials)) {
            return response()->json([
                'message' => 'Unauthenticated'
            ], 401);
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
        $user = User::withDeactivated()->where('email', $request->email)->first();
        if(!$user) {
            return response()->json([
                'message' => 'Email address is not registered'
            ], 404);
        }
        $response = $this->broker()->sendResetLink($request->only('email'));
        if($response !== Password::RESET_LINK_SENT) {
            return response()->json([
                'message' => 'There was an error sending password reset email'
            ], 500);
        }
        return response()->json([
            'message' => 'Password reset email has been sent'
        ], 200);
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
            return response()->json([
                'message' => 'There was an error resetting the password'
            ], 500);
        }
        return response()->json([
            'message' => 'Password has been reset'
        ], 200);
    }
    
    /**
     * Get the broker to be used during password reset.
     *
     * @return \Illuminate\Contracts\Auth\PasswordBroker
     */
    private function broker() {
        $passwordBrokerManager = new PasswordBrokerManager(app());
        return $passwordBrokerManager->broker();
    }
    
    /**
     * Request email verification.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function requestEmailVerification() {
        $user = $this->getUser();
        return $user->sendEmailVerificationNotification();
    }
    
    /**
     * Verify email address.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function verifyEmail(Request $request) {
        $this->validate($request, [
            'email' => 'required|string|email|max:255',
            'token' => 'required|string',
        ], [
            'email.required' => 'Email not provided',
            'token.required' => 'Token not provided'
        ]);
        $user = User::where('email', $request->email)->firstOrFail();
        return $user->markEmailAsVerified($request->token);
    }
    
    /**
     * Check if an email address has been verified.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function checkEmailVerification(Request $request) {
        $user = $this->getUser();
        if(!$user->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Email has not been verified',
                'email_verified' => false
            ], 200);
        }
        return response()->json([
            'message' => 'Email has been verified',
            'email_verified' => true
        ], 200);
    }
    
    /**
     * Return the currently authenticated user.
     *
     * @return \App\User
     */
    private function getUser() {
        $user = Auth::user();
        return $user;
    }
}
