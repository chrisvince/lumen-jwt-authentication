<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\User;

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
                'deactivate'
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
            'password' => app('hash')->make($request->input('password'), [])
        ]);
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
            return response()->json(['error' => 'Unauthenticated'], 401);
        }
        if (!$user->trashed()) {
            return response()->json(['error' => 'User is already active'], 400);
        }
        if(!app('hash')->check($request->password, $user->password)) {
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
}
