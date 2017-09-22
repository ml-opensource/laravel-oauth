<?php

namespace Fuzz\Auth\Tests;

use Fuzz\Auth\Models\Traits\ChecksScopes;
use LucaDegasperi\OAuth2Server\Facades\Authorizer;
use LucaDegasperi\OAuth2Server\OAuth2ServerServiceProvider;
use LucaDegasperi\OAuth2Server\Storage\FluentStorageServiceProvider;

class ChecksScopesTest extends ApplicationTestCase
{
	protected function getPackageProviders($app)
	{
		return [
			FluentStorageServiceProvider::class,
			OAuth2ServerServiceProvider::class,
		];
	}

	public function testItChecksScopes()
	{
		$checker = new ChecksScopesTestStubClass;

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(true);

		$has_scopes = $checker->hasOneOfScopes('admin');

		$this->assertTrue($has_scopes);
	}

	public function testItRequiresOneOfManyScalarArguments()
	{
		$checker = new ChecksScopesTestStubClass;

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(true);

		// Passing scope is marked with /***/
		$has_scopes = $checker->hasOneOfScopes(/***/'admin'/***/, 'nonexistent', 'animal');

		$this->assertTrue($has_scopes);
	}

	public function testItRequiresOneOfManyScalarArgumentsFails()
	{
		$checker = new ChecksScopesTestStubClass;

		Authorizer::shouldReceive('hasScope')->once()
			->with('not admin')->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with('nonexistent')->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with('animal')->andReturn(false);

		// Passing scope is marked with /***/
		$has_scopes = $checker->hasOneOfScopes('not admin', 'nonexistent', 'animal');

		$this->assertFalse($has_scopes);
	}

	public function testItRequiresOneOfManyNonScalarArgumentsSucceeds()
	{
		$checker = new ChecksScopesTestStubClass;

		Authorizer::shouldReceive('hasScope')->once()
			->with(['animal', 'hamburger'])->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with(['employee', 'elephant'])->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with(['user', 'admin', 'owner'])->andReturn(true);

		// Passing scope is marked with /***/
		$has_scopes = $checker->hasOneOfScopes(['animal', 'hamburger'], ['employee', 'elephant'], /***/['user', 'admin', 'owner']/***/, ['tenant', 'stuffed animal']);

		$this->assertTrue($has_scopes);
	}

	public function testItRequiresOneOfManyNonScalarArgumentsFails()
	{
		$checker = new ChecksScopesTestStubClass;

		Authorizer::shouldReceive('hasScope')->once()
			->with(['animal', 'hamburger'])->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with(['employee', 'elephant'])->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with(['not user', 'not admin'])->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with(['tenant', 'stuffed animal'])->andReturn(false);

		// Passing scope is marked with /***/
		$has_scopes = $checker->hasOneOfScopes(['animal', 'hamburger'], ['employee', 'elephant'], ['not user', 'not admin'], ['tenant', 'stuffed animal']);

		$this->assertFalse($has_scopes);
	}

	public function testItRequiresAllOfSingleArrayArgumentsSucceeds()
	{
		$checker = new ChecksScopesTestStubClass;

		Authorizer::shouldReceive('hasScope')->once()
			->with(['user', 'admin', 'owner'])->andReturn(true);

		// Passing scope is marked with /***/
		$has_scopes = $checker->hasOneOfScopes(/***/['user', 'admin', 'owner']/***/);

		$this->assertTrue($has_scopes);
	}

	public function testItRequiresAllOfSingleArrayArgumentsFails()
	{
		$checker = new ChecksScopesTestStubClass;

		Authorizer::shouldReceive('hasScope')->once()
			->with(['user', 'admin', 'owner', 'not a scope'])->andReturn(false);

		// Passing scope is marked with /***/
		$has_scopes = $checker->hasOneOfScopes(['user', 'admin', 'owner', 'not a scope']);

		$this->assertFalse($has_scopes);
	}

	public function testItRequiresOneOfManyMixedSucceeds()
	{
		$checker = new ChecksScopesTestStubClass;

		Authorizer::shouldReceive('hasScope')->once()
			->with('dog')->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with('animal')->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(true);

		// Passing scope is marked with /***/
		$has_scopes = $checker->hasOneOfScopes('dog', 'animal', /***/'admin'/***/, ['user', 'admin', 'owner', 'fake scope']);

		$this->assertTrue($has_scopes);
	}

	public function testItRequiresOneOfManyMixedFails()
	{
		$checker = new ChecksScopesTestStubClass;

		Authorizer::shouldReceive('hasScope')->once()
			->with('dog')->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with('animal')->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with('not admin')->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with(['user', 'admin', 'owner', 'fake scope'])->andReturn(false);

		// Passing scope is marked with /***/
		$has_scopes = $checker->hasOneOfScopes('dog', 'animal', 'not admin', ['user', 'admin', 'owner', 'fake scope']);

		$this->assertFalse($has_scopes);
	}
}

class ChecksScopesTestStubClass
{
	use ChecksScopes;
}