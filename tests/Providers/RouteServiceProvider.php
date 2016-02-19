<?php

namespace Fuzz\Auth\Tests\Providers;

use Fuzz\RestTests\Tests\Controllers\Controller;
use Illuminate\Routing\Router;
use Illuminate\Foundation\Support\Providers\RouteServiceProvider as BaseRouteServiceProvider;

class RouteServiceProvider extends BaseRouteServiceProvider
{
	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		// Do nothing
	}

	/**
	 * Define the routes for the application.
	 *
	 * @param  \Illuminate\Routing\Router  $router
	 * @return void
	 */
	public function map(Router $router)
	{
		$router->group(['namespace' => 'Fuzz\\Auth\\Tests\\Controllers'], function (Router $router) {
			$router->post(
				'oauth/access_token', 'OAuthController@issueAccessToken'
			);
		});

		$router->group(['namespace' => 'Fuzz\\Auth\\Tests\\Controllers', 'prefix' => Controller::API_VERSION], function (Router $router) {
		});
	}
}
