<p>JWT stands for JSON Web Token. It is a compact, URL-safe means of representing claims between two parties. In the context of Laravel, JWT is often used for user authentication and authorization. Laravel does not have built-in support for JWT out of the box, but you can use third-party packages to integrate JWT functionality
</p>

<p align="center">
 
</p>

## Setup JWT with Laravel

- User Register API
- Login API
- Profile API
- Refresh Token API
- Logout API

## Step 1
Run composer command,

composer require tymon/jwt-auth

## Step 2
Open app.php file from /config folder.

- Search for “providers“, add this line of code into it.

'providers' => ServiceProvider::defaultProviders()->merge([
    //...
    Tymon\JWTAuth\Providers\LaravelServiceProvider::class,
])->toArray(),

- Search for “aliases“, add these lines of code into it.

'aliases' => Facade::defaultAliases()->merge([
   //...
   'Jwt' => Tymon\JWTAuth\Providers\LaravelServiceProvider::class,
   'JWTFactory' => Tymon\JWTAuth\Facades\JWTFactory::class,
   'JWTAuth' => Tymon\JWTAuth\Facades\JWTAuth::class,
])->toArray(),

## Step 3
Publish jwt.php (jwt settings) file. Run this command to terminal,

php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
It will copy a file jwt.php inside /config folder.

## Step 4
Run migration

php artisan migrate
It will migrate all pending migrations of application.

## Step 5
Generate jwt secret token value,

php artisan jwt:secret
It updates .env file with jwt secret key

## Step 6
Open auth.php file from /config folder.

- Search for “guards“. Add these lines of code into it,

'guards' => [
    //...
    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
],

## Step 7
Update User.php (User model class file).

Open User.php file from /app/Models folder.
<p>
<?php
​
namespace App\Models;
​
// use Illuminate\Contracts\Auth\MustVerifyEmail;

use Illuminate\Database\Eloquent\Factories\HasFactory;

use Illuminate\Foundation\Auth\User as Authenticatable;

use Illuminate\Notifications\Notifiable;

use Laravel\Sanctum\HasApiTokens;

use Tymon\JWTAuth\Contracts\JWTSubject;
​
class User extends Authenticatable implements JWTSubject

{

    use HasApiTokens, HasFactory, Notifiable;
​
    /**
     * The attributes that are mass assignable. 
     *
     * @var array<int, string>
     */

    protected $fillable = [

        'name',

        'email',

        'password',
    ];
​
    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */

    protected $hidden = [

        'password',

        'remember_token',
    ];
​
    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [

        'email_verified_at' => 'datetime',

        'password' => 'hashed',
    ]; 
​
    public function getJWTIdentifier()

    {

      return $this->getKey();

    }
​
    public function getJWTCustomClaims()

    {

      return [];

    }
}
​
Successfully, you have setup JWT auth package into application.

Now, you have a middleware which you can use to protect api routes i.e “jwt”

</p>

## Step 8
API Controller Settings
Run this command to create API controller class,

php artisan make:controller Api/ApiController
It will create a file named ApiController.php inside /app/Http/Controllers folder.

Read More: How To Upload File with Progress Bar in Laravel 10 Tutorial

Open file and write this complete code into it,

<?php
​
namespace App\Http\Controllers\Api;
 
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
​
class ApiController extends Controller
{
    // User Register (POST, formdata)
    public function register(Request $request){

        // User Model
        User::create([
            "name" => $request->name,
            "email" => $request->email,
            "password" => Hash::make($request->password)
        ]);
​
        // Response
        return response()->json([
            "status" => true,
            "message" => "User registered successfully"
        ]);
    }
​
    // User Login (POST, formdata)
    public function login(Request $request){
​
        // JWTAuth
        $token = JWTAuth::attempt([
            "email" => $request->email,
            "password" => $request->password
        ]);
​
        if(!empty($token)){
​
            return response()->json([
                "status" => true,
                "message" => "User logged in succcessfully",
                "token" => $token
            ]);
        }
​
        return response()->json([
            "status" => false,
            "message" => "Invalid details"
        ]);
    }
​
    // User Profile (GET)
    public function profile(){
​
        $userdata = auth()->user();
​
        return response()->json([
            "status" => true,
            "message" => "Profile data",
            "data" => $userdata
        ]);
    } 
​
    // To generate refresh token value
    public function refreshToken(){
        
        $newToken = auth()->refresh();
​
        return response()->json([
            "status" => true,
            "message" => "New access token",
            "token" => $newToken
        ]);
    }
​
    // User Logout (GET)
    public function logout(){
        
        auth()->logout();
​
        return response()->json([
            "status" => true,
            "message" => "User logged out successfully"
        ]);
    }
}
​
## Step 9

Open api.php file from /routes folder. Add these routes into it,

//...
use App\Http\Controllers\Api\ApiController;
​
Route::post("register", [ApiController::class, "register"]);
Route::post("login", [ApiController::class, "login"]);
​
Route::group([
    "middleware" => ["jwt"]
], function(){
​
    Route::get("profile", [ApiController::class, "profile"]);
    Route::get("refresh", [ApiController::class, "refreshToken"]);
    Route::get("logout", [ApiController::class, "logout"]);
});

## Step 10

Create a Custom Middleware:

Create a new middleware using the following command in your terminal:


php artisan make:middleware JwtMiddleware
This will create a new middleware file in the app/Http/Middleware directory.

Update the Middleware Logic:

Open the newly created JwtMiddleware.php file and update the handle method to include your JWT validation logic. You can use the JWTAuth facade for this purpose.

<?php

namespace App\Http\Middleware;

use Closure;
use Tymon\JWTAuth\Facades\JWTAuth;

class JwtMiddleware
{
    public function handle($request, Closure $next)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => 'Unauthorized.'], 401);
        }

        return $next($request);
    }
}
Register the Middleware:

Open the app/Http/Kernel.php file and add your middleware to the $routeMiddleware array:
Copy code
protected $routeMiddleware = [
    // ...
    'jwt' => \App\Http\Middleware\JwtMiddleware::class,
];
Update Routes:

Change the middleware in your routes file to use the newly created jwt middleware:
