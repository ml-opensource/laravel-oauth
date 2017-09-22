<?php

namespace Fuzz\Auth\Tests;

use Fuzz\Auth\Guards\OAuthGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use League\OAuth2\Server\Exception\AccessDeniedException;
use League\OAuth2\Server\Exception\InvalidRequestException;
use LucaDegasperi\OAuth2Server\Exceptions\NoActiveAccessTokenException;
use LucaDegasperi\OAuth2Server\Facades\Authorizer;
use LucaDegasperi\OAuth2Server\OAuth2ServerServiceProvider;
use LucaDegasperi\OAuth2Server\Storage\FluentStorageServiceProvider;
use Mockery;

class OAuthGuardTest extends ApplicationTestCase
{
	protected function getPackageProviders($app)
	{
		return [
			FluentStorageServiceProvider::class,
			OAuth2ServerServiceProvider::class,
		];
	}

	public function testItReturnsNullIfUserNotFound()
	{
		$provider = Mockery::mock(UserProvider::class);
		$guard = new OAuthGuard($provider);

		Authorizer::shouldReceive('validateAccessToken')->once()->andThrow(InvalidRequestException::class);
		$provider->shouldReceive('retrieveById')->never();

		$this->assertNull($guard->user());
	}

	public function testItReturnsNullIfUserNotFound2()
	{
		$provider = Mockery::mock(UserProvider::class);
		$guard = new OAuthGuard($provider);

		Authorizer::shouldReceive('validateAccessToken')->once()->andThrow(AccessDeniedException::class);
		$provider->shouldReceive('retrieveById')->never();

		$this->assertNull($guard->user());
	}

	public function testItReturnsNullIfUserNotFound3()
	{
		$provider = Mockery::mock(UserProvider::class);
		$guard = new OAuthGuard($provider);

		Authorizer::shouldReceive('validateAccessToken')->once()->andThrow(NoActiveAccessTokenException::class);
		$provider->shouldReceive('retrieveById')->never();

		$this->assertNull($guard->user());
	}

	public function testItFindsAndReturnsUser()
	{
		$provider = Mockery::mock(UserProvider::class);
		$guard = new OAuthGuard($provider);
		$user = Mockery::mock(Model::class);

		Authorizer::shouldReceive('validateAccessToken')->once();
		Authorizer::shouldReceive('getResourceOwnerId')->once()->andReturn('some_id');
		$provider->shouldReceive('retrieveById')->with('some_id')->once()->andReturn($user);

		$this->assertSame($user, $guard->user());
	}

	public function testItReturnsFalseIfCredentialsNotValid()
	{
		$provider = Mockery::mock(UserProvider::class);
		$guard = new OAuthGuard($provider);

		$provider->shouldReceive('retrieveByCredentials')->with([
			'foo' => 'bar',
		])->once()->andReturn(null);

		$this->assertFalse($guard->validate([
			'foo' => 'bar',
		]));
	}

	public function testItReturnsTrueIfCredentialsNotValid()
	{
		$provider = Mockery::mock(UserProvider::class);
		$guard = new OAuthGuard($provider);
		$user = Mockery::mock(Authenticatable::class);

		$provider->shouldReceive('retrieveByCredentials')->with([
			'foo' => 'bar',
		])->once()->andReturn($user);

		$this->assertTrue($guard->validate([
			'foo' => 'bar',
		]));
	}
}
