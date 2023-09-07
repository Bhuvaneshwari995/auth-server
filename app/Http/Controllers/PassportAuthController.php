<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Socialite;


class PassportAuthController extends Controller
{

   public function register(Request $request) {
        $validator = Validator::make($request->all(), [
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users',
        'password' => 'required|string|min:8',
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
            }
            $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            ]);
            return response()->json(['user' => $user], 201);
            }




    public function login(Request $request) {
        $credentials = $request->only('email', 'password');
        if (Auth::attempt($credentials)) {
        $user = Auth::user();
        $token = $user->createToken('access-token')->accessToken;
        return response()->json(["data"=>$user,'token' => $token], 200);
        }else{
        return response()->json(['error' => 'Invalid credentials'], 401);
        }
    }



        public function sso(Request $request) {
            $token = $request->token;
            // Authenticate the user using the token
            $user = User::where('remember_token', $token)->first();
            if (!$user) {
            return response()->json(['error' => 'Invalid token'], 401);
            }
            // Log in the user and redirect to the client app
            Auth::login($user);
            return redirect($request->redirect_uri);
            }





            public function token (Request $request) {
         
                $redirect_uri = urlencode($request->redirect_uri);
           return $redirect_uri;
                // // Redirect to the authentication server
                // return redirect('http://auth-server/sso?redirect_uri='.$redirect_uri.'&token=' . Auth::user()->remember_token);


                }


//                 public function redirectToProvider(){
//                         return Socialite::driver('google')->redirect();
//                         }
//                 public function handleProviderCallback(){
//                         $user = Socialite::driver('google')->user();
// // Logic to authenticate the user
//                         return redirect('/home');
//                         }



}
