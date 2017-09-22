<?php

namespace Fuzz\Auth\Providers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\DB;
use LucaDegasperi\OAuth2Server\Facades\Authorizer;

class FuzzAuthUserProvider implements UserProvider
{
	/**
	 * User model class
	 *
	 * @var string
	 */
	private $user_model;

	/**
	 * Token input key
	 *
	 * @var string
	 */
	private $token_key;

	/**
	 * FuzzAuthUserProvider constructor.
	 *
	 * @param array $config
	 */
	public function __construct(array $config)
	{
		$this->validateConfig($config);

		$this->user_model = $config['model'];
		$this->token_key  = $config['token_key'];
	}

	/**
	 * Validate configuration options
	 *
	 * @param array $config
	 */
	public function validateConfig(array $config)
	{
		$required = [
			'model',
			'token_key',
		];

		foreach ($required as $require_key) {
			if (! isset($config[$require_key])) {
				throw new \LogicException("User Provider config is missing the $require_key configuration.");
			}
		}
	}

	/**
	 * Retrieve a user by their unique identifier.
	 *
	 * @param  mixed $identifier
	 * @return \Illuminate\Contracts\Auth\Authenticatable|null
	 */
	public function retrieveById($identifier)
	{
		$user_model = $this->user_model;

		return $user_model::whereId($identifier)->first();
	}

	/**
	 * Retrieve a user by their unique identifier and "remember me" token.
	 *
	 * @param  mixed  $identifier
	 * @param  string $token
	 * @return \Illuminate\Contracts\Auth\Authenticatable|null
	 */
	public function retrieveByToken($identifier, $token)
	{
		if (Authorizer::validateAccessToken(false, $token)) {
			return $this->retrieveById(Authorizer::getResourceOwnerId());
		}

		return null;
	}

	/**
	 * Retrieve a user by the given credentials.
	 *
	 * @param  array $credentials
	 * @return \Illuminate\Contracts\Auth\Authenticatable|null
	 */
	public function retrieveByCredentials(array $credentials)
	{
		if (Authorizer::validateAccessToken(false, $credentials[$this->token_key])) {
			$user_id = Authorizer::getResourceOwnerId();

			return $this->retrieveById($user_id);
		}

		return null;
	}

	/**
	 * Validate a user against the given credentials.
	 *
	 * @param  \Illuminate\Contracts\Auth\Authenticatable $user
	 * @param  array                                      $credentials
	 * @return bool
	 */
	public function validateCredentials(Authenticatable $user, array $credentials)
	{
		return ! is_null($this->retrieveByCredentials($credentials));
	}

	/**
	 * Revoke all sessions for the owner.
	 *
	 * Access tokens will be revoked through cascades.
	 *
	 * @todo: This should live in the OAuth2 package, but it does not currently provide a clean way
	 *      of revoking sessions and/or tokens in bulk.
	 *
	 * @param string  $owner_type
	 * @param integer $owner_id
	 */
	public static function revokeSessionsForOwnerTypeAndId($owner_type, $owner_id)
	{
		DB::table('oauth_sessions')->where('owner_type', '=', $owner_type)->where('owner_id', '=', $owner_id)->delete();
	}

	/**
	 * Update the "remember me" token for the given user in storage.
	 *
	 * @param  \Illuminate\Contracts\Auth\Authenticatable $user
	 * @param  string                                     $token
	 * @return void
	 */
	public function updateRememberToken(Authenticatable $user, $token)
	{
		// Do nothing
	}
}
