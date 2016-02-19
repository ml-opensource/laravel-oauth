<?php

namespace Fuzz\Auth\Tests;

use Carbon\Carbon;
use Fuzz\Auth\Models\OauthClient;
use Fuzz\Auth\Models\OauthScope;
use Fuzz\Auth\Tests\Models\User;
use Fuzz\RestTests\AuthTraits\OAuthTrait;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Exception\InvalidClientException;
use League\OAuth2\Server\Exception\InvalidRefreshException;
use League\OAuth2\Server\Exception\InvalidRequestException;
use League\OAuth2\Server\Exception\InvalidScopeException;

class RefreshTokenGrantTest extends ApiTestCase
{
	use OAuthTrait;

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

	public function testItCanExchangeRefreshTokenForAccessToken()
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

		$password_auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $this->getClient()
		);
		$auth          = $this->refreshToken($password_auth->refresh_token, $this->getClient());

		// Assert we get a token returned
		$this->assertTrue(isset($auth->access_token) && ! is_null($auth->access_token));

		foreach (
			[
				'user',
				'admin',
			] as $scope
		) {
			$this->assertTrue(in_array($scope, $auth->scopes));
		}

		$this->assertEquals('Bearer', $auth->token_type);

		// Assert the token was created and scopes were applied to it
		$this->assertNotNull(
			DB::table('oauth_access_token_scopes')->where('access_token_id', '=', $auth->access_token)
				->where('scope_id', '=', 'user')->first()
		);
		$this->assertNotNull(
			DB::table('oauth_access_token_scopes')->where('access_token_id', '=', $auth->access_token)
				->where('scope_id', '=', 'admin')->first()
		);
	}

	public function testItThrowsExceptionOnInvalidClientId()
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

		$client = $this->getClient();

		$password_auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);

		$client['client_id'] = 'invalid';

		$this->setExpectedException(InvalidClientException::class, 'Client authentication failed.');
		$auth = $this->refreshToken($password_auth->refresh_token, $client);
	}

	public function testItThrowsExceptionOnNullClientId()
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

		$client = $this->getClient();

		$password_auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);

		$client['client_id'] = null;

		$this->setExpectedException(InvalidRequestException::class, 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "client_id" parameter.');
		$auth = $this->refreshToken($password_auth->refresh_token, $client);
	}

	public function testItThrowsExceptionOnInvalidClientSecret()
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

		$client = $this->getClient();

		$password_auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);

		$client['client_secret'] = 'invalid';

		$this->setExpectedException(InvalidClientException::class, 'Client authentication failed.');
		$auth = $this->refreshToken($password_auth->refresh_token, $client);
	}

	public function testItThrowsExceptionOnNullClientSecret()
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

		$client = $this->getClient();

		$password_auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);

		$client['client_secret'] = null;

		$this->setExpectedException(InvalidRequestException::class, 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "client_secret" parameter.');
		$auth = $this->refreshToken($password_auth->refresh_token, $client);
	}

	public function testItThrowsExceptionOnNullRefreshToken()
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

		$client = $this->getClient();

		$password_auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);

		$this->setExpectedException(InvalidRequestException::class, 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "refresh_token" parameter.');
		$auth = $this->refreshToken(null, $client);
	}

	public function testItThrowExceptionOnInvalidRefreshToken()
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

		$client = $this->getClient();

		$password_auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);

		$this->setExpectedException(InvalidRefreshException::class, 'The refresh token is invalid.');
		$auth = $this->refreshToken('invalid token', $client);
	}

	public function testItThrowsExceptionIfRefreshTokenExpired()
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

		$client = $this->getClient();

		$password_auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);

		DB::table('oauth_refresh_tokens')->where('id', $password_auth->refresh_token)->update(
			[
				'expire_time' => time() - 10000 // Set the expire time to way before now
			]
		);

		$this->setExpectedException(InvalidRefreshException::class, 'The refresh token is invalid.');
		$auth = $this->refreshToken($password_auth->refresh_token, $client);
	}

	public function testItReturnsNewTokenWithOriginalScopes()
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

		$client = $this->getClient();

		$password_auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);

		$auth = $this->refreshToken($password_auth->refresh_token, $client);

		foreach(['user', 'admin'] as $scope) {
			$this->assertTrue(in_array($scope, $auth->scopes));
		}
	}

	public function testItThrowsExceptionIfRefreshTokenRequestsExtraScopes()
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

		$client = $this->getClient();

		$password_auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
		], $client);

		$this->setExpectedException(InvalidScopeException::class, 'The requested scope is invalid, unknown, or malformed. Check the "admin" scope.');
		$auth = $this->refreshToken($password_auth->refresh_token, $client, 'refresh_token', $user->username, ['user', 'admin']);

		$this->assertEquals(['user'], $auth->scopes);
	}
}
