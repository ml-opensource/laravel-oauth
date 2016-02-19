<?php

namespace Fuzz\Auth\OAuth\Grants;

use Fuzz\Auth\Models\AgentInterface;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\Exception\InvalidRequestException;
use League\OAuth2\Server\Exception\InvalidScopeException;

class PasswordGrantVerifier
{
	/**
	 * @var Config
	 */
	protected $config;
	/**
	 * @var Request
	 */
	protected $request;

	/**
	 * @var object
	 */
	protected $user;
	/**
	 * @var Auth
	 */
	protected $auth;

	/**
	 * If true, throw exceptions when a scope that the user can't access is requested.
	 * If false, don't throw exceptions but still only allow the user access to scopes they can access.
	 *
	 * @var bool
	 */
	public $exception_on_invalid_scope = false;

	/**
	 * @param Request $request
	 * @param Config  $config
	 * @param Auth    $auth
	 */
	public function __construct(Request $request, Config $config, Auth $auth)
	{
		$this->request    = $request;
		$this->config     = $config;
		$this->auth       = $auth;
		$this->user_model = config('auth.providers.users.model');
	}

	/**
	 * @param $username
	 * @param $email
	 * @param $password
	 * @return bool
	 */
	private function validateCredentials($username, $email, $password)
	{
		$user_model = $this->user_model;
		if (! ((new $user_model) instanceof AgentInterface)) {
			throw new \LogicException('User model does not implement ' . AgentInterface::class . '.');
		}

		$query = $user_model::query();

		if (! is_null($username)) {
			$query->whereUsername($username);
		}

		// Allow users to log in with either username or email or both. But if both, require
		// both to match to the same user
		if (! is_null($email)) {
			$query->whereEmail($email);
		}

		if ($this->user = $query->first()) {
			if ($this->user->checkPassword($password)) {
				return $this->user->id;
			}
		}

		return false;
	}

	/**
	 * @throws InvalidRequestException
	 * @throws InvalidScopeException
	 */
	private function validateScopes()
	{
		$scopes_list = $this->request->get('scope');

		if (! is_string($scopes_list)) {
			throw new InvalidRequestException('scope');
		}

		$scopes_list = explode(config('oauth2.scope_delimiter', ','), $scopes_list);
		for ($i = 0; $i < count($scopes_list); $i++) {
			$scopes_list[$i] = trim($scopes_list[$i]);
			if ($scopes_list[$i] === '') {
				unset($scopes_list[$i]); // Remove any junk scopes
			}
		}

		$user_scopes = $this->user->scopes->lists('id')->toArray();

		if ($this->exception_on_invalid_scope || count($user_scopes) === 0) {
			// Diff the user's available scopes with the currently requested scopes
			$extra_scopes = array_diff($scopes_list, $user_scopes);

			foreach ($extra_scopes as $scope_item) {
				throw new InvalidScopeException($scope_item);
			}
		}

		// Return the scopes this user can access
		return array_intersect($scopes_list, $user_scopes);
	}

	/**
	 * @param      $username
	 * @param null $email
	 * @param      $password
	 * @return bool
	 * @throws \League\OAuth2\Server\Exception\InvalidRequestException
	 */
	public function verify($username = null, $email = null, $password)
	{
		// Require at least one
		if (is_null($username) && is_null($email)) {
			throw new InvalidRequestException('username, email');
		}

		if (! $this->validateCredentials($username, $email, $password)) {
			return ['scopes' => [], 'user_id' => false];
		}

		$accepted_scopes = $this->validateScopes();

		return ['scopes' => $accepted_scopes, 'user_id' => $this->user->id];
	}
}
