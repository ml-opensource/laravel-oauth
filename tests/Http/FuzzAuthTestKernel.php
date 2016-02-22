<?php

namespace Fuzz\Auth\Tests\Http;

use Fuzz\Auth\Middleware\OAuthenticateMiddleware;
use Orchestra\Testbench\Http\Kernel;

class FuzzAuthTestKernel extends Kernel
{
	/**
	 * The application's route middleware.
	 *
	 * These middleware may be assigned to groups or used individually.
	 *
	 * @var array
	 */
	protected $routeMiddleware = [
		'auth'       => OAuthenticateMiddleware::class,
	];

	/**
	 * Get the current array of route middleware
	 *
	 * @return array
	 */
	public function getRouteMiddleware()
	{
		return $this->routeMiddleware;
	}

	/**
	 * Set the current route middleware
	 *
	 * @param array $route_middleware
	 * @return array
	 */
	public function setRouteMiddleware(array $route_middleware)
	{
		return $this->routeMiddleware = $route_middleware;
	}
}
