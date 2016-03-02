<?php

namespace Fuzz\Auth\Guards;

use Fuzz\Auth\Models\AgentResolverInterface;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use League\OAuth2\Server\Exception\InvalidRequestException;

class OAuthGuard implements Guard
{
	use GuardHelpers;

	/**
	 * The request instance.
	 *
	 * @var \Illuminate\Http\Request
	 */
	protected $request;

	/**
	 * Create a new authentication guard.
	 *
	 * @param  \Illuminate\Contracts\Auth\UserProvider $provider
	 */
	public function __construct(UserProvider $provider)
	{
		if (! $provider instanceof AgentResolverInterface) {
			throw new \LogicException(get_class($provider) . ' does not implement ' . AgentResolverInterface::class);
		}
		$this->provider = $provider;
	}

	/**
	 * Get the currently authenticated user.
	 *
	 * @uses LucaDegasperi\OAuth2Server\Authorizer
	 *
	 * @return \Illuminate\Contracts\Auth\Authenticatable|null
	 */
	public function user()
	{
		// If we've already retrieved the user for the current request we can just
		// return it back immediately. We do not want to fetch the user data on
		// every call to this method because that would be tremendously slow.
		if (! is_null($this->user)) {
			return $this->user;
		}

		try {
			return $this->user = $this->provider->resolveAppAgent();
		} catch (InvalidRequestException $e) {
			return $this->user = null;
		}
	}

	/**
	 * Validates an access token and finds if it belongs to a user.
	 *
	 * @param array $credentials
	 *
	 * @return bool
	 */
	public function validate(array $credentials = [])
	{
		return ! is_null($this->provider->retrieveByCredentials($credentials));
	}
}
