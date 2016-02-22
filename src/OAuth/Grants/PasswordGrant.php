<?php

namespace Fuzz\Auth\OAuth\Grants;

use Fuzz\Auth\Models\OauthScopeEntity;
use Fuzz\Auth\Models\OauthTokenEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
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
		$accessToken = new OauthTokenEntity($this->server);
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

	/**
	 * Given a list of scopes, validate them and return an array of Scope entities
	 *
	 * @param string                                    $scopeParam  A string of scopes (e.g. "profile email birthday")
	 * @param \League\OAuth2\Server\Entity\ClientEntity $client      Client entity
	 * @param string|null                               $redirectUri The redirect URI to return the user to
	 *
	 * @return \League\OAuth2\Server\Entity\ScopeEntity[]
	 *
	 * @throws \League\OAuth2\Server\Exception\InvalidScopeException If scope is invalid, or no scopes passed when
	 *                                                               required
	 * @throws
	 */
	public function validateScopes($scopeParam = '', ClientEntity $client, $redirectUri = null)
	{
		$scopesList = explode($this->server->getScopeDelimiter(), $scopeParam);

		for ($i = 0; $i < count($scopesList); $i++) {
			$scopesList[$i] = trim($scopesList[$i]);
			if ($scopesList[$i] === '') {
				unset($scopesList[$i]); // Remove any junk scopes
			}
		}

		if ($this->server->scopeParamRequired() === true
			&& $this->server->getDefaultScope() === null
			&& count($scopesList) === 0
		) {
			throw new Exception\InvalidRequestException('scope');
		} elseif (count($scopesList) === 0 && $this->server->getDefaultScope() !== null) {
			if (is_array($this->server->getDefaultScope())) {
				$scopesList = $this->server->getDefaultScope();
			} else {
				$scopesList = [0 => $this->server->getDefaultScope()];
			}
		}

		$scopes = [];

		foreach ($scopesList as $scopeItem) {
			$scope = $this->server->getScopeStorage()->get(
				$scopeItem, $this->getIdentifier(), $client->getId()
			);

			if (($scope instanceof ScopeEntity) === false) {
				throw new Exception\InvalidScopeException($scopeItem, $redirectUri);
			}

			$scopes[$scope->getId()] = new OauthScopeEntity($this->server, $scope);
		}

		return $scopes;
	}
}
