Laravel OAuth
==============
An OAuth wrapper to bridge `lucadegasperi/oauth2-server-laravel` and Laravel's authentication system

## Setup
1. Require the composer package
1. Set up your project `AuthServiceProvider` to extend `Fuzz\Auth\Providers\AuthServiceProvider`
1. Follow instructions in `lucadegasperi/oauth2-server-laravel` to set it up.
1. Configure the `grant_types` array in `config/oauth2.php` to use the Fuzz grants (or extend/create your own)

	```
	'grant_types'             => [
		'password' => [
			'class' => \Fuzz\Auth\OAuth\Grants\PasswordGrant::class,
			'callback' => '\Fuzz\Auth\OAuth\Grants\PasswordGrantVerifier@verify',
			'access_token_ttl' => 7600,
		],
		'refresh_token' => [
			'class' => \Fuzz\Auth\OAuth\Grants\RefreshTokenGrant::class,
			'access_token_ttl' => 7600,
			'refresh_token_ttl' => 14600,
		],
	],
	```
1. Set up `config/auth.php`

	Set the default guard to `api`

	```
	'defaults' => [
	    'guard' => 'api',
	    'passwords' => 'users',
	],
	```
	Set the `api` guard to use `\Fuzz\Auth\Guards\OAuthGuard::class` as its
	driver

	```
	'api' => [
	    'driver' => \Fuzz\Auth\Guards\OAuthGuard::class,
	    'provider' => 'users',
	],
	```
	Set Laravel to use the `oauth` user provider and set your project's User class

	```
	'providers' => [
	    'users' => [
	        'driver' => 'oauth',
	        'model' => \Crub\User::class,
	        'token_key' => 'access_token',
	    ],
	],
	```

1. Create `app/Http/Middleware/OAuthMiddleware.php` and extend `Fuzz\Auth\Middleware\OAuthenticateMiddleware`. Add it to the `$routeMiddleware` array in `app/Http/Kernel.php
1. Your User class should implement the `Fuzz\Auth\Models\AgentInterface` and `Illuminate\Contracts\Auth\Authenticatable` their required methods

## Usage
### Protecting routes
Routes that require authentication can now be protected with the `auth` middleware:

```
$router->group(
    ['middleware' => 'auth'], function (Router $router) {
        $router->get('locations', 'LocationsController@index');
});
```
Within any authenticated route, you can use all the default Laravel `Auth` methods such as `Auth::user()` to resolve the currently authenticated user. `lucadegasperi/oauth2-server-laravel` provides a way to protect routes based on scope, but you can also use `Fuzz\Auth\Policies\RepositoryModelPolicy@requireScopes` to throw `League\OAuth2\Server\Exception\AccessDeniedException` exceptions when a user does not have the required scopes.

### Protecting resources
Laravel OAuth comes with a base `Fuzz\Auth\Policies\RepositoryModelPolicy` but you may create your own (implementing the `Fuzz\Auth\Policies\RepositoryModelPolicyInterface` might be helpful. Extending `Fuzz\Auth\Policies\RepositoryModelPolicy` will provide some base methods to ease writing policies for repositories.

Once a policy is set up and mapped to its model class, you may use it to check user permissions according to your policy:

```
 if (policy(ModelClass::class)->index($user, $postRepository)) {
 		// Index stuff
 }
```

### Resolving the current user
All of Laravel's `Auth` methods will work, so resolving the current user is as simple as `$user = Auth::user()`. `https://laravel.com/docs/5.2/authentication`.

`Auth` will use your default guard unless specified. A typical guard set up for an OAuth specced API would be having one for users accessing via a client and another for client-only requests. `Auth` provides a way to Currently there is only `Fuzz\Auth\Guards\OAuthGuard` which is responsible for resolving the user for a request.


## TODOs
1. Support client requests in their own guard and be compatible with the current user `OAuthGuard`
