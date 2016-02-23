<?php

namespace Fuzz\Auth\Tests;

use Carbon\Carbon;
use Fuzz\Auth\Models\OauthClient;
use Fuzz\Auth\Models\OauthScope;
use Fuzz\Auth\Models\Traits\ChecksScopes;
use Fuzz\Auth\Tests\Models\User;
use Fuzz\RestTests\AuthTraits\OAuthTrait;
use Illuminate\Support\Facades\DB;
use LucaDegasperi\OAuth2Server\Facades\Authorizer;

class ChecksScopesTest extends ApiTestCase
{
	use OAuthTrait;

	public function setUpScopeCheckTests(array $with_scopes)
	{
		$this->setUpOauthTest();

		$user           = new User;
		$user->username = 'aNewTestUser';
		$user->password = 'aUserPassword';
		$user->save();

		OauthScope::attachToUser(
			$user, $with_scopes
		);

		return $this->authenticate(
			$user->username, 'aUserPassword', [
			'user',
			'admin',
		], $this->getClient());
	}

	public function testItChecksScopes()
	{
		$this->setUpScopeCheckTests(['user', 'admin']);

		$checker = new UsesChecksScopesTrait;

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(true);

		$has_scopes = $checker->hasOneOfScopes('admin');

		$this->assertTrue($has_scopes);
	}

	public function testItRequiresOneOfManyScalarArguments()
	{
		$this->setUpScopeCheckTests(['user', 'admin', 'owner', 'human']);

		$checker = new UsesChecksScopesTrait;

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(true);

		// Passing scope is marked with /***/
		$has_scopes = $checker->hasOneOfScopes(/***/'admin'/***/, 'nonexistent', 'animal');

		$this->assertTrue($has_scopes);
	}

	public function testItRequiresOneOfManyScalarArgumentsFails()
	{
		$this->setUpScopeCheckTests(['user', 'admin', 'owner', 'human']);

		$checker = new UsesChecksScopesTrait;

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
		$this->setUpScopeCheckTests(['user', 'admin', 'owner', 'human']);

		$checker = new UsesChecksScopesTrait;

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
		$this->setUpScopeCheckTests(['user', 'admin', 'owner', 'human']);

		$checker = new UsesChecksScopesTrait;

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
		$this->setUpScopeCheckTests(['user', 'admin', 'owner', 'human']);

		$checker = new UsesChecksScopesTrait;

		Authorizer::shouldReceive('hasScope')->once()
			->with(['user', 'admin', 'owner'])->andReturn(true);

		// Passing scope is marked with /***/
		$has_scopes = $checker->hasOneOfScopes(/***/['user', 'admin', 'owner']/***/);

		$this->assertTrue($has_scopes);
	}

	public function testItRequiresAllOfSingleArrayArgumentsFails()
	{
		$this->setUpScopeCheckTests(['user', 'admin', 'owner', 'human']);

		$checker = new UsesChecksScopesTrait;

		Authorizer::shouldReceive('hasScope')->once()
			->with(['user', 'admin', 'owner', 'not a scope'])->andReturn(false);

		// Passing scope is marked with /***/
		$has_scopes = $checker->hasOneOfScopes(['user', 'admin', 'owner', 'not a scope']);

		$this->assertFalse($has_scopes);
	}

	public function testItRequiresOneOfManyMixedSucceeds()
	{
		$this->setUpScopeCheckTests(['user', 'admin', 'owner', 'human']);

		$checker = new UsesChecksScopesTrait;

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
		$this->setUpScopeCheckTests(['user', 'admin', 'owner', 'human']);

		$checker = new UsesChecksScopesTrait;

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

	public function createUserInDatabase(array $attributes)
	{
		$user = new User;

		foreach ($attributes as $key => $value) {
			$user->{$key} = $value;
		}

		$user->save();

		return $user;
	}
}

class UsesChecksScopesTrait
{
	use ChecksScopes;
}
