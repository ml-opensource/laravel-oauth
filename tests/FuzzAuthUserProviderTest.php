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
use LucaDegasperi\OAuth2Server\OAuth2ServerServiceProvider;
use LucaDegasperi\OAuth2Server\Storage\FluentStorageServiceProvider;
use Mockery;

class FuzzAuthUserProviderTest extends ApplicationTestCase
{
	protected function getPackageProviders($app)
	{
		return [
			FluentStorageServiceProvider::class,
			OAuth2ServerServiceProvider::class,
		];
	}

	public function testItFailsOnInvalidModelConfig()
	{
		$config = [
			'driver' => 'oauth',
			'token_key' => 'access_token'
		];

		$this->setExpectedException(\LogicException::class, 'User Provider config is missing the model configuration.');
		$provider = new FuzzAuthUserProvider($config);
	}

	public function testItFailsOnInvalidTokenKeyConfig()
	{
		$config = [
			'driver' => 'oauth',
			'model' => User::class,
		];

		$this->setExpectedException(\LogicException::class, 'User Provider config is missing the token_key configuration.');
		$provider = new FuzzAuthUserProvider($config);
	}

	public function testItCanRetrieveById()
	{
		$config = [
			'driver' => 'oauth',
			'model' => FuzzAuthUserProviderTestUserStub::class,
			'token_key' => 'access_token'
		];

		$provider = new FuzzAuthUserProvider($config);

		$this->assertSame(65785, $provider->retrieveById(FuzzAuthUserProviderTestUserStub::ID)->id);
	}

	public function testItReturnsNullOnRetrieveByIdIfNotExists()
	{
		$config = [
			'driver' => 'oauth',
			'model' => FuzzAuthUserProviderTestUserStub::class,
			'token_key' => 'access_token'
		];

		$provider = new FuzzAuthUserProvider($config);

		$this->assertNull($provider->retrieveById(1019));
	}

	public function testItRetrievesByToken()
	{
		$config = [
			'driver' => 'oauth',
			'model' => FuzzAuthUserProviderTestUserStub::class,
			'token_key' => 'access_token'
		];

		$provider = new FuzzAuthUserProvider($config);

		Authorizer::shouldReceive('validateAccessToken')->with(false, 'foo_token')->once()->andReturn(true);
		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn(65785);

		$this->assertSame(65785, $provider->retrieveByToken('id', 'foo_token')->id);
	}

	public function testItReturnsNullIfRetrievingByTokenByIdNotFound()
	{
		$config = [
			'driver' => 'oauth',
			'model' => FuzzAuthUserProviderTestUserStub::class,
			'token_key' => 'access_token'
		];

		$provider = new FuzzAuthUserProvider($config);

		Authorizer::shouldReceive('validateAccessToken')->with(false, 'foo_token')->once()->andReturn(true);
		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn(1242);

		$this->assertNull($provider->retrieveByToken('id', 'foo_token'));
	}

	public function testItRetrievesByCredentials()
	{
		$config = [
			'driver' => 'oauth',
			'model' => FuzzAuthUserProviderTestUserStub::class,
			'token_key' => 'access_token'
		];

		$provider = new FuzzAuthUserProvider($config);

		Authorizer::shouldReceive('validateAccessToken')->with(false, 'foo_token')->once()->andReturn(true);
		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn(65785);

		$this->assertSame(65785, $provider->retrieveByCredentials([
			'access_token' => 'foo_token'
		])->id);
	}

	public function testItValidatesCredentials()
	{
		$config = [
			'driver' => 'oauth',
			'model' => FuzzAuthUserProviderTestUserStub::class,
			'token_key' => 'access_token'
		];
		$mock = Mockery::mock(Authenticatable::class);

		$provider = new FuzzAuthUserProvider($config);

		Authorizer::shouldReceive('validateAccessToken')->with(false, 'foo_token')->once()->andReturn(true);
		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn(65785);

		$this->assertTrue($provider->validateCredentials($mock, [
			'access_token' => 'foo_token'
		]));
	}
}

class FuzzAuthUserProviderTestUserStub
{
	const ID = 65785;

	public static function whereId($id)
	{
		if ($id !== self::ID) {
			return new FailedQuery;
		}

		return new SuccessQuery;
	}
}

class SuccessQuery
{
	public function first()
	{
		$mock = Mockery::mock(Authenticatable::class);
		$mock->id = 65785;

		return $mock;
	}
}

class FailedQuery
{
	public function first()
	{
		return null;
	}
}