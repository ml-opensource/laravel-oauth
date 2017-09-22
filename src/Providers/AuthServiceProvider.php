<?php

namespace Fuzz\Auth\Providers;

use Fuzz\Auth\Guards\OAuthGuard;
use Illuminate\Support\Facades\Auth;
use LucaDegasperi\OAuth2Server\OAuth2ServerServiceProvider;
use LucaDegasperi\OAuth2Server\Storage\FluentStorageServiceProvider;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;

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
	}

	/**
	 * Set up the user provider
	 *
	 * @return void
	 */
	public function setUpAuthUserProvider()
	{
		Auth::provider(FuzzAuthUserProvider::class, function ($app, array $config) {
			return new FuzzAuthUserProvider($config);
		});
	}

	/**
	 * Extend the API auth provider
	 *
	 * @return void
	 */
	public function extendApiAuthProvider()
	{
		Auth::extend(OAuthGuard::class, function ($app, $name, array $config) {
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
