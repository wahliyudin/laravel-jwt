<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\Auth\LoginRequest;
use App\Http\Requests\Api\Auth\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {
        User::query()->create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return response()->json([
            'status' => true,
            'message' => 'User created successfully'
        ]);
    }

    public function login(LoginRequest $request)
    {
        $token = JWTAuth::attempt([
            'email' => $request->email,
            'password' => $request->password,
        ]);

        if ($token) {
            return response()->json([
                'status' => true,
                'message' => 'User logged in successfully',
                'token' => $token
            ]);
        }
        return response()->json([
            'status' => false,
            'message' => 'Invalid Login details',
        ]);
    }

    public function profile()
    {
        $user = Auth::guard('api')->user();

        return response()->json([
            'status' => true,
            'message' => 'Profile data',
            'user' => $user
        ]);
    }

    public function refreshToken()
    {
        $token = Auth::guard('api')->refresh();

        return response()->json([
            'status' => true,
            'message' => 'New Accsess token generated',
            'token' => $token
        ]);
    }

    public function logout()
    {
        Auth::guard('api')->logout();

        return response()->json([
            'status' => true,
            'message' => 'User logged out successfully'
        ]);
    }
}
