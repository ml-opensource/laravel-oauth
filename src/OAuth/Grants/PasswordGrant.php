<?php

namespace Fuzz\Auth\OAuth\Grants;

use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Grant\PasswordGrant as OauthPasswordGrant;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\RefreshTokenEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Event;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\Util\SecureKey;

class PasswordGrant extends OauthPasswordGrant
{
	/**
	 * Complete the password grant
	 *
	 * @return array
	 *
	 * @throws
	 */
	public function completeFlow()
	{
		// Get the required params
		$clientId = $this->server->getRequest()->request->get('client_id', $this->server->getRequest()->getUser());
		if (is_null($clientId)) {
			throw new Exception\InvalidRequestException('client_id');
		}

		$clientSecret = $this->server->getRequest()->request->get(
			'client_secret', $this->server->getRequest()->getPassword()
		);
		if (is_null($clientSecret)) {
			throw new Exception\InvalidRequestException('client_secret');
		}

		// Validate client ID and client secret
		$client = $this->server->getClientStorage()->get(
			$clientId, $clientSecret, null, $this->getIdentifier()
		);

		if (($client instanceof ClientEntity) === false) {
			$this->server->getEventEmitter()
				->emit(new Event\ClientAuthenticationFailedEvent($this->server->getRequest()));
			throw new Exception\InvalidClientException();
		}

		$username = $this->server->getRequest()->request->get('username', null);
		$email    = $this->server->getRequest()->request->get('email', null);

		// Require at least one
		if (is_null($username) && is_null($email)) {
			throw new Exception\InvalidRequestException('username, email');
		}

		$password = $this->server->getRequest()->request->get('password', null);
		if (is_null($password)) {
			throw new Exception\InvalidRequestException('password');
		}

		// Check if user's username and password are correct and custom validate scopes
		$validatedDetails = call_user_func($this->getVerifyCredentialsCallback(), $username, $email, $password);
		$userId           = $validatedDetails['user_id'];

		if ($userId === false) {
			$this->server->getEventEmitter()
				->emit(new Event\UserAuthenticationFailedEvent($this->server->getRequest()));
			throw new Exception\InvalidCredentialsException();
		}

		// Validate any scopes that are in the request. Implode because validateScopes expects a string
		$scopes = $this->validateScopes(implode(',', $validatedDetails['scopes']), $client);

		// Create a new session
		$session = new SessionEntity($this->server);
		$session->setOwner('user', $userId);
		$session->associateClient($client);

		// Generate an access token
		$accessToken = new AccessTokenEntity($this->server);
		$accessToken->setId(SecureKey::generate());
		$accessToken->setExpireTime($this->getAccessTokenTTL() + time());

		// Associate scopes with the session and access token
		foreach ($scopes as $scope) {
			$session->associateScope($scope);
		}

		foreach ($session->getScopes() as $scope) {
			$accessToken->associateScope($scope);
		}

		$this->server->getTokenType()->setSession($session);
		$this->server->getTokenType()->setParam('access_token', $accessToken->getId());
		$this->server->getTokenType()->setParam('expires_in', $this->getAccessTokenTTL());

		// Associate a refresh token if set
		if ($this->server->hasGrantType('refresh_token')) {
			$refreshToken = new RefreshTokenEntity($this->server);
			$refreshToken->setId(SecureKey::generate());
			$refreshToken->setExpireTime($this->server->getGrantType('refresh_token')->getRefreshTokenTTL() + time());
			$this->server->getTokenType()->setParam('refresh_token', $refreshToken->getId());
		}

		// Save everything
		$session->save();
		$accessToken->setSession($session);
		$accessToken->save();

		if ($this->server->hasGrantType('refresh_token')) {
			$refreshToken->setAccessToken($accessToken);
			$refreshToken->save();
		}

		$response = $this->server->getTokenType()->generateResponse();

		// Return scopes with the response
		$response['scopes'] = array_keys($scopes);

		return $response;
	}
}
