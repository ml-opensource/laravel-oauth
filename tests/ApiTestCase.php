<?php

namespace Fuzz\Auth\Tests;

use Fuzz\Auth\Models\OauthClient;
use Fuzz\Auth\OAuth\Grants\PasswordGrant;
use Fuzz\Auth\OAuth\Grants\RefreshTokenGrant;
use Fuzz\Auth\Tests\Exceptions\Handler;
use Fuzz\Auth\Tests\Http\FuzzAuthTestKernel;
use Fuzz\Auth\Tests\Models\User;
use Fuzz\Auth\Tests\Providers\RouteServiceProvider;
use Fuzz\RestTests\BaseRestTestCase;
use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel as LaravelKernel;
use LucaDegasperi\OAuth2Server\OAuth2ServerServiceProvider;
use LucaDegasperi\OAuth2Server\Storage\FluentStorageServiceProvider;
use Mockery;
use Orchestra\Testbench\Traits\ApplicationTrait;

abstract class ApiTestCase extends BaseRestTestCase
{
	use ApplicationTrait;

	/**
	 * Artisan kernel storage
	 *
	 * @var \Illuminate\Contracts\Console\Kernel
	 */
	protected $artisan;

	/**
	 * @var \Illuminate\Contracts\Console\Kernel|\Fuzz\Auth\Tests\Http\FuzzAuthTestKernel
	 */
	protected $kernel;

	/**
	 * The base URL to use while testing the application.
	 *
	 * @var string
	 */
	protected $baseUrl = 'http://localhost';

	/**
	 * API Version
	 *
	 * @var string
	 */
	public $api_version = '1.0';

	/**
	 * Token URI
	 *
	 * @var string
	 */
	public $oauth_url = 'oauth/access_token';

	/**
	 * OAuth client class storage
	 *
	 * @var string
	 */
	public $oauth_client_class = OAuthClient::class;

	/**
	 * Set up tests
	 */
	public function setUp()
	{
		if (! $this->app) {
			$this->refreshApplication();
		}

		$this->artisan = $this->app->make(ConsoleKernel::class);

		$this->artisan->call(
			'migrate', [
				'--database' => 'testbench',
				'--path'     => '../../../../tests/migrations',
			]
		);
	}

	/**
	 * Set up environment configurations
	 *
	 * @param $app
	 */
	protected function getEnvironmentSetUp($app)
	{
		$app['config']->set('database.default', 'testbench');
		$app['config']->set(
			'database.connections.testbench', [
				'driver'   => 'sqlite',
				'database' => ':memory:',
				'prefix'   => '',
			]
		);

		$app['config']->set('oauth2', $this->oauthConfig());
		$app['config']->set(
			'auth.providers', [
			'users' => [
				'driver'    => 'oauth',
				'model'     => User::class,
				'token_key' => 'access_token',
			],
		]);

		// We don't want to use the testbench exception handler because it doesn't actually throw an exception our tests
		// can catch
		$app->bind(ExceptionHandler::class, Handler::class);
	}

	/**
	 * Resolve application HTTP Kernel implementation.
	 *
	 * @param  \Illuminate\Foundation\Application  $app
	 *
	 * @return void
	 */
	protected function resolveApplicationHttpKernel($app)
	{
		$app->singleton(LaravelKernel::class, FuzzAuthTestKernel::class);

		$this->kernel = $app->make(LaravelKernel::class);
	}

	/**
	 * Clean up
	 */
	public function tearDown()
	{
		if (class_exists('Mockery')) {
			Mockery::close();
		}

		if ($this->app) {
			foreach ($this->beforeApplicationDestroyedCallbacks as $callback) {
				call_user_func($callback);
			}

			$this->app->flush();

			$this->app = null;
		}

		if (property_exists($this, 'serverVariables')) {
			$this->serverVariables = [];
		}
	}

	/**
	 * Get package providers.
	 *
	 * @param  \Illuminate\Foundation\Application $app
	 * @return array
	 */
	protected function getPackageProviders($app)
	{
		return [
			RouteServiceProvider::class,
			FluentStorageServiceProvider::class,
			OAuth2ServerServiceProvider::class,
		];
	}

	/**
	 * Return an oauth config
	 *
	 * @return array
	 */
	public function oauthConfig()
	{
		return [
			'database'                => 'default',
			'grant_types'             => [
				'password'      => [
					'class'            => PasswordGrant::class,
					'callback'         => '\Fuzz\Auth\OAuth\Grants\PasswordGrantVerifier@verify',
					'access_token_ttl' => 7600,
				],
				'refresh_token' => [
					'class'             => RefreshTokenGrant::class,
					'access_token_ttl'  => 7600,
					'refresh_token_ttl' => 14600,
				],
			],
			'token_type'              => 'League\OAuth2\Server\TokenType\Bearer',
			'state_param'             => false,
			'scope_param'             => false,
			'scope_delimiter'         => ',',
			'default_scope'           => null,
			'access_token_ttl'        => 3600,
			'limit_clients_to_grants' => false,
			'limit_clients_to_scopes' => false,
			'limit_scopes_to_grants'  => false,
			'http_headers_only'       => false,
		];
	}
}
