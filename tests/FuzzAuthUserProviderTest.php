<?php

namespace Fuzz\Auth\Tests;

use Fuzz\Auth\Models\AgentInterface;
use Fuzz\Auth\Models\AgentResolverInterface;
use Fuzz\Auth\Providers\FuzzAuthUserProvider;
use Fuzz\Auth\Tests\Models\NotAgentUser;
use Fuzz\Auth\Tests\Models\User;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use LucaDegasperi\OAuth2Server\Facades\Authorizer;

class FuzzAuthUserProviderTest extends ApiTestCase
{
	public function createUserInDatabase(array $attributes)
	{
		$user = new User;

		foreach ($attributes as $key => $value) {
			$user->{$key} = $value;
		}

		$user->save();

		return $user;
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

	public function testItImplementsUserProviderAndAgentResolverInterface()
	{
		$config = [
			'driver' => 'oauth',
			'model' => User::class,
			'token_key' => 'access_token'
		];

		$provider = new FuzzAuthUserProvider($config);

		$this->assertTrue($provider instanceof UserProvider);
		$this->assertTrue($provider instanceof AgentResolverInterface);
	}

	public function testItFailsGracefullyOnInvalidModelConfig()
	{
		$config = [
			'driver' => 'oauth',
			'token_key' => 'access_token'
		];

		$this->setExpectedException(\LogicException::class, 'User Provider config is missing the model configuration.');
		$provider = new FuzzAuthUserProvider($config);
	}

	public function testItFailsGracefullyOnInvalidTokenKeyConfig()
	{
		$config = [
			'driver' => 'oauth',
			'model' => User::class,
		];

		$this->setExpectedException(\LogicException::class, 'User Provider config is missing the token_key configuration.');
		$provider = new FuzzAuthUserProvider($config);
	}

	public function testItCanRetrieveUserById()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		$user_by_id = $provider->retrieveById($user->id);

		$this->assertTrue($user_by_id instanceof Authenticatable);
		$this->assertTrue($user_by_id instanceof AgentInterface);
		$this->assertTrue($user_by_id instanceof Model);
		$this->assertEquals($user->id, $user_by_id->id);
		$this->assertEquals($user->username, $user_by_id->username);
	}

	public function testItRetrieveNullIfUserDoesNotExist()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		$user_by_id = $provider->retrieveById(9999); // Doesn't exist

		$this->assertNull($user_by_id);
	}

	public function testItCanRetrieveByToken()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		Authorizer::shouldReceive('validateAccessToken')->once()
			->with(false, 'arbitraryString')->andReturn(true);

		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn($user->id);

		$user_by_token = $provider->retrieveByToken($user->id, 'arbitraryString');

		$this->assertTrue($user_by_token instanceof Authenticatable);
		$this->assertTrue($user_by_token instanceof AgentInterface);
		$this->assertTrue($user_by_token instanceof Model);
		$this->assertEquals($user->id, $user_by_token->id);
		$this->assertEquals($user->username, $user_by_token->username);
	}

	public function testItReturnsNullIfTokenIsInvalid()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		Authorizer::shouldReceive('validateAccessToken')->once()
			->with(false, 'arbitraryString')->andReturn(false);

		Authorizer::shouldReceive('getResourceOwnerId')->never();

		$user_by_token = $provider->retrieveByToken($user->id, 'arbitraryString');

		$this->assertNull($user_by_token);
	}

	public function testItReturnsNullTokenUserIfItDoesNotExist()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		Authorizer::shouldReceive('validateAccessToken')->once()
			->with(false, 'arbitraryString')->andReturn(true);

		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn(9999); // doesn't exist

		$user_by_token = $provider->retrieveByToken($user->id, 'arbitraryString');

		$this->assertNull($user_by_token);
	}

	public function testItCanRetrieveByCredentials()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		Authorizer::shouldReceive('validateAccessToken')->once()
			->with(false, 'arbitraryString')->andReturn(true);

		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn($user->id);

		$user_by_credentials = $provider->retrieveByCredentials(['access_token' => 'arbitraryString']);

		$this->assertTrue($user_by_credentials instanceof Authenticatable);
		$this->assertTrue($user_by_credentials instanceof AgentInterface);
		$this->assertTrue($user_by_credentials instanceof Model);
		$this->assertEquals($user->id, $user_by_credentials->id);
		$this->assertEquals($user->username, $user_by_credentials->username);
	}

	public function testItReturnsNullIfCredentialsAreInvalid()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		Authorizer::shouldReceive('validateAccessToken')->once()
			->with(false, 'arbitraryString')->andReturn(true);

		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn(9999); // Doesn't exist

		$user_by_credentials = $provider->retrieveByCredentials(['access_token' => 'arbitraryString']);

		$this->assertNull($user_by_credentials);
	}

	public function testItCanValidateCredentials()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		Authorizer::shouldReceive('validateAccessToken')->once()
			->with(false, 'arbitraryString')->andReturn(true);

		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn($user->id); // Doesn't exist

		$is_valid = $provider->validateCredentials($user, ['access_token' => 'arbitraryString']);

		$this->assertTrue($is_valid);
	}

	public function testItReturnsFalseIfCredentialsAreInvalid()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		Authorizer::shouldReceive('validateAccessToken')->once()
			->with(false, 'arbitraryString')->andReturn(false);

		Authorizer::shouldReceive('getResourceOwnerId')->never();

		$is_valid = $provider->validateCredentials($user, ['access_token' => 'arbitraryString']);

		$this->assertFalse($is_valid);
	}

	public function testItReturnsFalseIfCredentialsAreValidButUserIsNot()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		Authorizer::shouldReceive('validateAccessToken')->once()
			->with(false, 'arbitraryString')->andReturn(true);

		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn(9999); // Doesn't exist

		$is_valid = $provider->validateCredentials($user, ['access_token' => 'arbitraryString']);

		$this->assertFalse($is_valid);
	}

	public function testItThrowsExceptionIfUserDoesNotImplementAgentInterface()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider(NotAgentUser::class);

		Authorizer::shouldReceive('validateAccessToken')->never();

		Authorizer::shouldReceive('getResourceOwnerId')->never();

		$this->setExpectedException(\LogicException::class, 'User model does not implement ' .  AgentInterface::class  . '.');
		$is_valid = $provider->validateCredentials((new NotAgentUser), ['access_token' => 'arbitraryString']);

		$this->assertFalse($is_valid);
	}

	public function testItCanResolveAppAgent()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		Authorizer::shouldReceive('validateAccessToken')->once()->andReturn(true);

		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn($user->id);

		$resolved_user = $provider->resolveAppAgent();

		$this->assertTrue($resolved_user instanceof Authenticatable);
		$this->assertTrue($resolved_user instanceof AgentInterface);
		$this->assertTrue($resolved_user instanceof Model);
		$this->assertEquals($user->id, $resolved_user->id);
		$this->assertEquals($user->username, $resolved_user->username);
	}

	public function testItReturnsNullIfAgentIsNotResolved()
	{
		$user_data = [
			'username' => 'FuzzUser',
			'password' => 'securePassword1'
		];

		$user = $this->createUserInDatabase($user_data);
		$provider = $this->getProvider();

		Authorizer::shouldReceive('validateAccessToken')->once()->andReturn(false);

		Authorizer::shouldReceive('getResourceOwnerId')->never(); // Doesn't exist

		$resolved_user = $provider->resolveAppAgent();

		$this->assertNull($resolved_user);
	}

	// @todo what's the best way to test this?
	public function testItCanRevokeSessionsForOwnerTypeAndId()
	{

	}
}
