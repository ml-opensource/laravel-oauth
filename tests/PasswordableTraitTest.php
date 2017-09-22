<?php

namespace Fuzz\Auth\Tests;

use Fuzz\Auth\Models\Traits\PasswordableTrait;
use Illuminate\Support\Facades\Hash;
use LucaDegasperi\OAuth2Server\OAuth2ServerServiceProvider;
use LucaDegasperi\OAuth2Server\Storage\FluentStorageServiceProvider;

class PasswordableTraitTest extends ApplicationTestCase
{
	public function testItSetsPasswordAttributeAndCanCheckPassword()
	{
		$user = new PasswordableTraitTestStubClass;

		$user->setPasswordAttribute('password');

		$this->assertNotSame('password', $user->attributes['password']); // Should be hashed

		$this->assertTrue(Hash::check('password', $user->attributes['password']));
	}

	public function testItCanSetPasswordTokenAttribute()
	{
		$user = new PasswordableTraitTestStubClass;

		$user->setPasswordTokenAttribute('foo');

		$this->assertNotSame('foo', $user->attributes['password_token']); // Should be hashed

		$this->assertTrue(Hash::check('foo', $user->attributes['password_token']));
	}

	public function testItCanCheckPassword()
	{
		$user = new PasswordableTraitTestStubClass;

		$user->setPasswordAttribute('password');

		$this->assertFalse($user->checkPassword('foo'));
		$this->assertFalse($user->checkPassword('baz'));
		$this->assertTrue($user->checkPassword('password'));
	}

	public function testItCanForgePasswordToken()
	{
		$user = new PasswordableTraitTestStubClass;

		$token = $user->forgePasswordToken();

		$this->assertSame($token, $user->password_token);
	}

	public function testItChecksTokenValiditityBeforeChangingPassword()
	{
		$user = new PasswordableTraitTestStubClass;

		$user->setPasswordAttribute('password');
		$user->setPasswordTokenAttribute('foo');

		$user->changePassword('not_foo', 'some_foo');

		$this->assertFalse($user->checkPassword('some_foo'));
		$this->assertTrue($user->checkPassword('password'));

		$user->changePassword('foo', 'some_foo');

		$this->assertFalse($user->checkPassword('password'));
		$this->assertTrue($user->checkPassword('some_foo'));
	}

	protected function getPackageProviders($app)
	{
		return [
			FluentStorageServiceProvider::class,
			OAuth2ServerServiceProvider::class,
		];
	}
}

class PasswordableTraitTestStubClass
{
	use PasswordableTrait;

	public $password_token;

	public $attributes = [];

	public function save()
	{
		return true;
	}

	public function revokeSessions()
	{
		return true;
	}
}