<?php

namespace Fuzz\Auth\Providers;

use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Auth;
use Fuzz\Auth\Guards\OAuthGuard;

class AuthServiceProvider extends ServiceProvider
{
	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		$this->registerOAuthProviders();
		$this->registerCommands();
	}

	/**
	 * Register any application authentication / authorization services.
	 *
	 * @param  \Illuminate\Contracts\Auth\Access\Gate $gate
	 * @return void
	 */
	public function boot(GateContract $gate)
	{
		$this->registerPolicies($gate); // @todo not needed?

		Auth::provider(
			'oauth', function ($app, array $config) {
				return new FuzzAuthUserProvider($config);
		});

		// Register an OAuthGuard to be used
		Auth::extend(
			OAuthGuard::class, function ($app, $name, array $config) {
				return new OAuthGuard(Auth::createUserProvider($config['provider']));
		});
	}

	/**
	 * Register the service providers associated with the
	 * lucadegasperi/oauth2-server-laravel package.
	 *
	 * @return void
	 */
	protected function registerOAuthProviders()
	{
		$this->app->register(new FluentStorageServiceProvider($this->app));
		$this->app->register(new OAuth2ServerServiceProvider($this->app));
	}
}
