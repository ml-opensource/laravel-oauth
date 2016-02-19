<?php

namespace Fuzz\Auth\Tests;

use Carbon\Carbon;
use Fuzz\Auth\Models\AgentInterface;
use Fuzz\Auth\Models\OauthClient;
use Fuzz\Auth\Models\OauthScope;
use Fuzz\Auth\Tests\Models\NotAgentUser;
use Fuzz\Auth\Tests\Models\User;
use Fuzz\RestTests\AuthTraits\OAuthTrait;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Exception\InvalidClientException;
use League\OAuth2\Server\Exception\InvalidCredentialsException;
use League\OAuth2\Server\Exception\InvalidRequestException;

class PasswordGrantTest extends ApiTestCase
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
							'created_at' => \Carbon\Carbon::now(),
							'updated_at' => \Carbon\Carbon::now(),
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

	public function testItCanAuthenticateAndReturnTokenWithScopes()
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
		], $this->getClient()
		);

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

		$client['client_id'] = 'invalid';

		$this->setExpectedException(InvalidClientException::class, 'Client authentication failed.');
		$auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);
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

		$client['client_id'] = null;

		$this->setExpectedException(InvalidRequestException::class, 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "client_id" parameter.');
		$auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);
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

		$client['client_secret'] = 'invalid';

		$this->setExpectedException(InvalidClientException::class, 'Client authentication failed.');
		$auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);
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

		$client['client_secret'] = null;

		$this->setExpectedException(InvalidRequestException::class, 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "client_secret" parameter.');
		$auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $client);
	}

	public function testItThrowsExceptionIfUsernameIsNull()
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

		$client['username'] = null;

		$this->setExpectedException(InvalidRequestException::class, 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "username, email" parameter.');
		$auth = $this->authenticate(
			null, 'aUserPassword', [
			'user',
			'admin',
		], $client);
	}

	public function testItThrowsExceptionIfEmailIsNull()
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

		$client['email'] = null;

		$this->setExpectedException(InvalidRequestException::class, 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "username, email" parameter.');
		$auth = $this->authenticate(
			null, 'aUserPassword', [
			'user',
			'admin',
		], $client, 'password', true);
	}

	public function testItThrowsExceptionIfPasswordIsNull()
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

		$this->setExpectedException(InvalidRequestException::class, 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "password" parameter.');
		$auth = $this->authenticate(
			$user->username, null, [
			'user',
			'admin',
		], $client);
	}

	public function testItThrowsExceptionWhenCredentialsAreInvalid()
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

		$this->setExpectedException(InvalidCredentialsException::class, 'The user credentials were incorrect.');
		$auth = $this->authenticate(
			$user->username, 'notThisUsersPassword', [
			'user',
			'admin',
		], $client);
	}

	public function testItFiltersOutJunkScopes()
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

		$auth = $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'',
		], $client);
	}

	public function testItDoesNotThrowExceptionOnInvalidScopeParamIfScopeIsNotRequired()
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

		$auth = $this->authenticate(
			$user->username, 'aUserPassword', [], $client);
	}

	public function testItThrowsExceptionOnInvalidScopeParam()
	{
		$this->setUpOauthTest();

		Config::set('oauth2.scope_param', true);

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

		$this->setExpectedException(InvalidRequestException::class, 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "scope" parameter.');
		$auth = $this->authenticate(
			$user->username, 'aUserPassword', [], $client);
	}

	public function testItReturnsDefaultScopeIfNoScopesRequestedAndDefaultScopeIsSet()
	{
		$this->setUpOauthTest();

		Config::set('oauth2.default_scope', 'user');

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

		$auth = $this->authenticate(
			$user->username, 'aUserPassword', [], $client);

		$this->assertEquals(['user'], $auth->scopes);
	}

	public function testItReturnsDefaultScopesIfNoScopesRequestedAndDefaultScopesAreSet()
	{
		$this->setUpOauthTest();

		Config::set('oauth2.default_scope', ['user', 'admin']);

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

		$auth = $this->authenticate(
			$user->username, 'aUserPassword', [], $client);

		$this->assertEquals(['user', 'admin'], $auth->scopes);
	}

	public function testItDoesNotTryToFindInvalidScope()
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

		$auth = $this->authenticate(
			$user->username, 'aUserPassword', ['junkScope'], $client);

		$this->assertEquals([], $auth->scopes);
	}

	public function testItThrowsExceptionIfUserModelDoesNotImplementAgentInterface()
	{
		$this->setUpOauthTest();

		Config::set('auth.providers.users.model', NotAgentUser::class);

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

		$this->setExpectedException(\LogicException::class, 'User model does not implement ' . AgentInterface::class . '.');
		$auth = $this->authenticate(
			$user->username, 'aUserPassword', ['admin', 'user'], $client);
	}

	public function testItCanAuthenticateWithEmail()
	{
		$this->setUpOauthTest();

		$user           = new User;
		$user->email    = 'aNewTestUser@emails.com';
		$user->password = 'aUserPassword';
		$user->save();

		OauthScope::attachToUser(
			$user, [
				'user',
				'admin',
			]
		);

		$client = $this->getClient();

		$auth = $this->authenticate(
			$user->email, 'aUserPassword', ['admin', 'user'], $client, 'password', true);

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

	public function testItThrowsExceptionIfScopesAreNotPassedAsString()
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

		$request_data = [
			'password'      => 'aUserPassword',
			'client_id'     => $client['client_id'],
			'client_secret' => $client['client_secret'],
			'grant_type'    => 'password',
			'scope'         => [
				'admin',
				'user'
			],
		];

		$request_data['username'] = 'aNewTestUser';

		$this->setExpectedException(InvalidRequestException::class, 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "scope" parameter.');
		$this->post($this->oauthUrl(), $request_data)->getJson();
	}
}
