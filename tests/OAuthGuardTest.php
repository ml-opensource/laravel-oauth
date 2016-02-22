<?php

namespace Fuzz\Auth\Tests;

use Carbon\Carbon;
use Fuzz\Auth\Guards\OAuthGuard;
use Fuzz\Auth\Middleware\OAuthenticateMiddleware;
use Fuzz\Auth\Models\AgentResolverInterface;
use Fuzz\Auth\Models\OauthClient;
use Fuzz\Auth\Models\OauthScope;
use Fuzz\Auth\Providers\AuthServiceProvider;
use Fuzz\Auth\Providers\FuzzAuthUserProvider;
use Fuzz\Auth\Tests\Models\User;
use Fuzz\Auth\Tests\Providers\BadAuthUserProvider;
use Fuzz\Auth\Tests\Providers\RouteServiceProvider;
use Fuzz\RestTests\AuthTraits\OAuthTrait;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Exception\AccessDeniedException;
use League\OAuth2\Server\Exception\InvalidRequestException;
use LucaDegasperi\OAuth2Server\OAuth2ServerServiceProvider;
use LucaDegasperi\OAuth2Server\Storage\FluentStorageServiceProvider;

class OAuthGuardTest extends ApiTestCase
{
	use OAuthTrait;

	public function createUserInDatabase(array $attributes)
	{
		$user = new User;

		foreach ($attributes as $key => $value) {
			$user->{$key} = $value;
		}

		$user->save();

		return $user;
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
			AuthServiceProvider::class,
		];
	}

	protected function getEnvironmentSetUp($app)
	{
		parent::getEnvironmentSetUp($app);
		$app['config']->set(
			'auth.guards', [
				'web' => [
					'driver' => 'session',
					'provider' => 'users',
				],

				'api' => [
					'driver' => OAuthGuard::class,
					'provider' => 'users',
				],
			]
		);
	}

	public function getProvider($model_class = User::class, $token_key = 'access_token', $driver = 'oauth')
	{
		$config = [
			'driver' => $driver,
			'model' => $model_class,
			'token_key' => $token_key
		];

		return new FuzzAuthUserProvider($config);
	}

	public function testItCanResolveGuardUser()
	{
		$this->setUpOauthTest();

		$user           = new User;
		$user->username = 'aNewTestUser';
		$user->password = 'aUserPassword';
		$user->save();

		OauthScope::attachToUser(
			$user, [
				'user',
				'admin',
			]
		);

		$auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $this->getClient());

		$credentials = [
			'access_token' => $auth->access_token,
		];

		Auth::once($credentials);

		$resolved_user = Auth::user();

		$this->assertTrue($resolved_user instanceof User);
		$this->assertEquals($user->username, $resolved_user->username);
	}

	public function testItThrowsExceptionOnInvalidToken()
	{
		$this->setUpOauthTest();

		$user           = new User;
		$user->username = 'aNewTestUser';
		$user->password = 'aUserPassword';
		$user->save();

		OauthScope::attachToUser(
			$user, [
				'user',
				'admin',
			]
		);

		$auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $this->getClient());

		$credentials = [
			'access_token' => $auth->access_token . 'junk',
		];

		$this->setExpectedException(AccessDeniedException::class, 'The resource owner or authorization server denied the request.');
		Auth::once($credentials);
	}

	public function testItRequiresAgentResolverInterfaceForUserProvider()
	{
		$config = [
			'driver' => 'oauth',
			'model' => User::class,
			'token_key' => 'access_token',
		];

		$provider = new BadAuthUserProvider($config);

		$this->setExpectedException(\LogicException::class, get_class($provider) . ' does not implement ' . AgentResolverInterface::class);
		$token_key = $config['token_key'];
		$guard = new OAuthGuard($provider, $token_key);
	}

	public function testItThrowsAccessDeniedExceptionOnInvalidAccessToken()
	{
		$this->api_version = '';

		$authed_route = $this->url('auth/authedRoute');

		$this->setExpectedException(AccessDeniedException::class, 'The resource owner or authorization server denied the request.');
		$this->get($authed_route, ['Authorization' => 'Bearer notAValidToken'])
			->seeJson(['status' => 'Success.']);
	}

	public function testItThrowsInvalidRequestExceptionOnMissingAccessToken()
	{
		$this->api_version = '';

		$authed_route = $this->url('auth/authedRoute');

		$this->setExpectedException(InvalidRequestException::class, 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "access token" parameter.');
		$this->get($authed_route, [])
			->seeJson(['status' => 'Success.']);
	}

	public function testUnauthedCanAccessUnauthedRoute()
	{
		$this->api_version = '';

		$not_authed_route = $this->url('auth/notAuthedRoute');

		$this->get($not_authed_route, [])
			->seeStatusCode(200)
			->seeJson(['status' => 'Success']);
	}

	public function testMiddlewareCanGrantAccessToAuthedRouteForAuthedUser()
	{
		$this->setUpOauthTest();
		$user = $this->createUserInDatabase([
			'username' => 'testUser',
			'password' => 'testUserPassword',
		]);

		OauthScope::attachToUser(
			$user, [
				'user',
				'admin',
			]
		);

		$auth = $this->authenticate(
			$user->username, 'testUserPassword', [
			'user',
			'admin',
		], $this->getClient());

		$auth_header = $this->getAuthorizationHeader($user->username);

		$this->api_version = '';

		$authed_route = $this->url('auth/authedRoute');

		$this->get($authed_route, $auth_header)
			->seeStatusCode(200)
			->seeJson(['status' => 'Success']);
	}

	public function testMiddlewareCanGrantAccessToNotAuthedRouteForAuthedUser()
	{
		$this->setUpOauthTest();
		$user = $this->createUserInDatabase([
			'username' => 'testUser',
			'password' => 'testUserPassword',
		]);

		OauthScope::attachToUser(
			$user, [
				'user',
				'admin',
			]
		);

		$auth = $this->authenticate(
			$user->username, 'testUserPassword', [
			'user',
			'admin',
		], $this->getClient());

		$auth_header = $this->getAuthorizationHeader($user->username);

		$this->api_version = '';

		$not_authed_route = $this->url('auth/notAuthedRoute');

		$this->get($not_authed_route, $auth_header)
			->seeStatusCode(200)
			->seeJson(['status' => 'Success']);
	}

	public function testItThrowsLogicExceptionIfNoGuardDefined()
	{
		$this->api_version = '';

		$not_authed_route = $this->url('auth/noGuardRoute');

		$this->setExpectedException(\LogicException::class, OAuthenticateMiddleware::class .' called with no guard defined.');
		$this->get($not_authed_route, [])
			->seeStatusCode(200)
			->seeJson(['status' => 'Success']);
	}

	public function testItCanResolveAuthedUser()
	{
		$this->setUpOauthTest();
		$user = $this->createUserInDatabase([
			'username' => 'testUser',
			'password' => 'testUserPassword',
		]);

		OauthScope::attachToUser(
			$user, [
				'user',
				'admin',
			]
		);

		$auth = $this->authenticate(
			$user->username, 'testUserPassword', [
			'user',
			'admin',
		], $this->getClient());

		$auth_header = $this->getAuthorizationHeader($user->username);

		$this->api_version = '';

		$authed_route = $this->url('auth/authedRoute');

		$this->get($authed_route, $auth_header)
			->seeStatusCode(200)
			->seeJson(['status' => 'Success']);

		$authed_user = Auth::guard('api')->user();
		$this->assertEquals($user->id, $authed_user->id);
		$this->assertEquals($user->username, $authed_user->username);
	}

	public function testItCanResolveAuthedUserIfAlreadyResolved()
	{
		$this->setUpOauthTest();
		$user = $this->createUserInDatabase([
			'username' => 'testUser',
			'password' => 'testUserPassword',
		]);

		OauthScope::attachToUser(
			$user, [
				'user',
				'admin',
			]
		);

		$auth = $this->authenticate(
			$user->username, 'testUserPassword', [
			'user',
			'admin',
		], $this->getClient());

		$auth_header = $this->getAuthorizationHeader($user->username);

		$this->api_version = '';

		$authed_route = $this->url('auth/authedRoute');

		$this->get($authed_route, $auth_header)
			->seeStatusCode(200)
			->seeJson(['status' => 'Success']);

		$first_authed_user = Auth::guard('api')->user();
		$this->assertEquals($user->id, $first_authed_user->id);
		$this->assertEquals($user->username, $first_authed_user->username);

		$second_authed_user = Auth::guard('api')->user();
		$this->assertEquals($user->id, $second_authed_user->id);
		$this->assertEquals($user->username, $second_authed_user->username);
	}

	public function testItCanValidateAuthedUser()
	{
		$this->setUpOauthTest();
		$user = $this->createUserInDatabase([
			'username' => 'testUser',
			'password' => 'testUserPassword',
		]);

		OauthScope::attachToUser(
			$user, [
				'user',
				'admin',
			]
		);

		$auth = $this->authenticate(
			$user->username, 'testUserPassword', [
			'user',
			'admin',
		], $this->getClient());

		$auth_header = $this->getAuthorizationHeader($user->username);

		$this->api_version = '';

		$authed_route = $this->url('auth/authedRoute');

		$this->get($authed_route, $auth_header)
			->seeStatusCode(200)
			->seeJson(['status' => 'Success']);

		$this->assertTrue(Auth::guard('api')->validate([
			'access_token' => $this->getToken($user->username),
		]));
	}

	public function createScopes()
	{
		$scopes = [
			[
				'id'          => 'user',
				'description' => 'User',
				'created_at'  => Carbon::now(),
				'updated_at'  => Carbon::now(),
			],
			[
				'id'          => 'admin',
				'description' => 'Admin',
				'created_at'  => Carbon::now(),
				'updated_at'  => Carbon::now(),
			],
		];

		DB::table('oauth_scopes')->insert($scopes);
	}

	public function createClients()
	{
		$clients = [
			[
				'id'     => 'client1',
				'secret' => 'client1secret',
				'name'   => 'CMS',
				'scopes' => [
					'user',
					'admin',
				],
			],
		];

		foreach ($clients as $client) {
			$instance         = new OauthClient;
			$instance->id     = $client['id'];
			$instance->secret = $client['secret'];
			$instance->name   = $client['name'];
			$instance->save();

			DB::table('oauth_client_scopes')->insert(
				array_map(
					function ($scope) use ($client) {
						return [
							'client_id'  => $client['id'],
							'scope_id'   => $scope,
							'created_at' => Carbon::now(),
							'updated_at' => Carbon::now(),
						];
					}, $client['scopes']
				)
			);
		}
	}

	public function getClient()
	{
		return [
			'client_id'     => 'client1',
			'client_secret' => 'client1secret',
		];
	}

	public function setUpOauthTest()
	{
		$this->createScopes();
		$this->createClients();
	}
}
