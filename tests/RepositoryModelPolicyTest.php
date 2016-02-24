<?php

namespace Fuzz\Auth\Tests;

use Carbon\Carbon;
use Fuzz\Auth\Guards\OAuthGuard;
use Fuzz\Auth\Models\OauthClient;
use Fuzz\Auth\Models\OauthScope;
use Fuzz\Auth\Policies\ChecksGatePolicies;
use Fuzz\Auth\Providers\AuthServiceProvider;
use Fuzz\Auth\Tests\Models\Post;
use Fuzz\Auth\Tests\Models\User;
use Fuzz\Auth\Tests\Policies\PostPolicy;
use Fuzz\Auth\Tests\Policies\SimplePostPolicy;
use Fuzz\Auth\Tests\Providers\PolicyServiceProvider;
use Fuzz\Auth\Tests\Providers\RouteServiceProvider;
use Fuzz\MagicBox\EloquentRepository;
use Fuzz\RestTests\AuthTraits\OAuthTrait;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Exception\AccessDeniedException;
use LucaDegasperi\OAuth2Server\Facades\Authorizer;
use LucaDegasperi\OAuth2Server\OAuth2ServerServiceProvider;
use LucaDegasperi\OAuth2Server\Storage\FluentStorageServiceProvider;

class RepositoryModelPolicyTest extends ApiTestCase
{
	use ChecksGatePolicies, OAuthTrait;

	public function testItCanSetGatePolicyClass()
	{
		$this->setPolicyClass(Post::class);

		$this->assertEquals(Post::class, $this->policy_class);
	}

	public function testItCanGetGatePolicyClass()
	{
		$this->policy_class = Post::class;

		$this->assertEquals(Post::class, $this->getPolicyClass());
	}

	public function testItReturnsPolicyInstance()
	{
		$this->setPolicyClass(Post::class);

		$this->assertTrue($this->policy() instanceof SimplePostPolicy);
	}

	public function testSimplePolicyCanGrantForIndex()
	{
		$user = $this->setUpPolicyTest(['user']);
		$repository = $this->getRepository(Post::class);

		$policy = new SimplePostPolicy;

		Authorizer::shouldReceive('hasScope')->once()
			->with('user')->andReturn(true);

		$this->assertTrue($policy->index($user, $repository));
	}

	public function testSimplePolicyCanDenyForIndex()
	{
		$user = $this->setUpPolicyTest(['neither']);
		$repository = $this->getRepository(Post::class);

		$policy = new SimplePostPolicy;

		Authorizer::shouldReceive('hasScope')->once()
			->with('user')->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(false);

		$this->assertFalse($policy->index($user, $repository));
	}

	public function testSimplePolicyCanGrantForShow()
	{
		$user = $this->setUpPolicyTest(['user']);
		$repository = $this->getRepository(Post::class);

		$policy = new SimplePostPolicy;
		$post = new Post;

		Authorizer::shouldReceive('hasScope')->once()
			->with('user')->andReturn(true);

		$this->assertTrue($policy->show($user, $repository, $post));
	}

	public function testSimplePolicyCanDenyForShow()
	{
		$user = $this->setUpPolicyTest(['neither']);
		$repository = $this->getRepository(Post::class);

		$policy = new SimplePostPolicy;
		$post = new Post;

		Authorizer::shouldReceive('hasScope')->once()
			->with('user')->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(false);

		$this->assertFalse($policy->show($user, $repository, $post));
	}

	public function testSimplePolicyCanGrantForUpdate()
	{
		$user = $this->setUpPolicyTest(['admin']);
		$repository = $this->getRepository(Post::class);

		$policy = new SimplePostPolicy;
		$post = new Post;

		Authorizer::shouldReceive('hasScope')
			->with('user')->never();

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(true);

		$this->assertTrue($policy->update($user, $repository, $post));
	}

	public function testSimplePolicyCanDenyForUpdate()
	{
		$user = $this->setUpPolicyTest(['neither']);
		$repository = $this->getRepository(Post::class);

		$policy = new SimplePostPolicy;
		$post = new Post;

		Authorizer::shouldReceive('hasScope')
			->with('user')->never();

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(false);

		$this->assertFalse($policy->update($user, $repository, $post));
	}

	public function testSimplePolicyCanGrantForStore()
	{
		$user = $this->setUpPolicyTest(['admin']);
		$repository = $this->getRepository(Post::class);

		$policy = new SimplePostPolicy;

		Authorizer::shouldReceive('hasScope')
			->with('user')->never();

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(true);

		$this->assertTrue($policy->store($user, $repository));
	}

	public function testSimplePolicyCanDenyForStore()
	{
		$user = $this->setUpPolicyTest(['neither']);
		$repository = $this->getRepository(Post::class);

		$policy = new SimplePostPolicy;

		Authorizer::shouldReceive('hasScope')
			->with('user')->never();

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(false);

		$this->assertFalse($policy->store($user, $repository));
	}

	public function testSimplePolicyCanGrantForDestroy()
	{
		$user = $this->setUpPolicyTest(['admin']);
		$repository = $this->getRepository(Post::class);

		$policy = new SimplePostPolicy;
		$post = new Post;

		Authorizer::shouldReceive('hasScope')
			->with('user')->never();

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(true);

		$this->assertTrue($policy->destroy($user, $repository, $post));
	}

	public function testSimplePolicyCanDenyForDestroy()
	{
		$user = $this->setUpPolicyTest(['neither']);
		$repository = $this->getRepository(Post::class);

		$policy = new SimplePostPolicy;
		$post = new Post;

		Authorizer::shouldReceive('hasScope')
			->with('user')->never();

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(false);

		$this->assertFalse($policy->destroy($user, $repository, $post));
	}

	public function testRepositoryModelPolicyAppliesFilters()
	{
		$user = $this->setUpPolicyTest(['admin']);
		$repository = $this->getRepository(Post::class);

		$policy = new PostPolicy;

		Authorizer::shouldReceive('hasScope')->once()
			->with('user')->andReturn(false);

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(true);

		$this->assertTrue($policy->index($user, $repository));

		$filters_applied = $repository->getFilters();

		$this->assertEquals(1, count($filters_applied));
		$this->assertEquals('someFilter', $filters_applied[0]());
	}

	public function testItThrowsExceptionIfRequiredScopesMissing()
	{
		$this->setUpPolicyTest(['user']);

		$policy = new PostPolicy;

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(false);

		$this->setExpectedException(AccessDeniedException::class, 'The resource owner or authorization server denied the request.');
		$policy->requireScopes('admin');
	}

	public function testItRequireScopesReturnsTrueIfRequiredScopesExist()
	{
		$this->setUpPolicyTest(['admin']);

		$policy = new PostPolicy;

		Authorizer::shouldReceive('hasScope')->once()
			->with('admin')->andReturn(true);

		$this->assertTrue($policy->requireScopes('admin'));
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
			PolicyServiceProvider::class,
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
			[
				'id'          => 'neither',
				'description' => 'Neither',
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

	public function setUpPolicyTest(array $user_with_scopes, $token_scopes = ['user', 'admin'])
	{
		$this->setUpOauthTest();

		$user           = new User;
		$user->username = 'aNewTestUser';
		$user->password = 'aUserPassword';
		$user->save();

		OauthScope::attachToUser(
			$user, $user_with_scopes
		);

		$auth = $this->authenticate(
			$user->username, 'aUserPassword', $token_scopes, $this->getClient());

		return $user;
	}

	/**
	 * Retrieve a sample repository for testing.
	 *
	 * @param string|null $model_class
	 * @param array       $input
	 * @return \Fuzz\MagicBox\EloquentRepository|static
	 */
	private function getRepository($model_class = null, array $input = [])
	{
		if (! is_null($model_class)) {
			return (new EloquentRepository)->setModelClass($model_class)->setDepthRestriction(3)->setInput($input);
		}

		return new EloquentRepository;
	}
}
