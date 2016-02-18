<?php

namespace Fuzz\Auth\Models;

use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use LucaDegasperi\OAuth2Server\Facades\Authorizer;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;

// @todo grant should set this class as token
class OauthToken extends AccessTokenEntity implements TokenInterface
{
	// @todo define interface
	private $user;

	/**
	 * Format the local scopes array
	 *
	 * @param  \League\OAuth2\Server\Entity\ScopeEntity[]
	 *
	 * @return array
	 */
	protected function formatScopes($unformatted = [])
	{
		// @todo validateScopes in password grant should return this class for scopes
		if (is_null($unformatted)) {
			return [];
		}

		$scopes = [];
		foreach ($unformatted as $scope) {
			if ($scope instanceof ScopeEntity) {
				$scopes[$scope->getId()] = $scope;
			}
		}

		return $scopes;
	}

	/**
	 * String representation of object
	 *
	 * @link  http://php.net/manual/en/serializable.serialize.php
	 * @return string the string representation of the object or null
	 * @since 5.1.0
	 */
	public function serialize()
	{
		return $this->getId();
	}

	/**
	 * Constructs the object
	 *
	 * @link  http://php.net/manual/en/serializable.unserialize.php
	 * @param string $serialized <p>
	 *                           The string representation of the object.
	 *                           </p>
	 * @return void
	 * @since 5.1.0
	 */
	public function unserialize($serialized)
	{
		$this->setId($serialized); // @todo ??
	}

	/**
	 * Returns the user roles.
	 *
	 * @return RoleInterface[] An array of RoleInterface instances.
	 */
	public function getRoles()
	{
		return $this->getScopes();
	}

	/**
	 * Returns the user credentials.
	 *
	 * @return mixed The user credentials
	 */
	public function getCredentials()
	{
		// TODO: Implement getCredentials() method.
	}

	/**
	 * Returns a user representation.
	 *
	 * @return mixed Can be a UserInterface instance, an object implementing a __toString method,
	 *               or the username as a regular string
	 *
	 * @see AbstractToken::setUser()
	 */
	public function getUser()
	{
		if (! is_null($this->user)) {
			return $this->user;
		}

		return $this->user = User::find($this->getSession()->getOwnerId());
	}

	/**
	 * Sets a user.
	 *
	 * @param mixed $user
	 */
	public function setUser($user)
	{
		$this->user = $user;
	}

	/**
	 * Returns the username.
	 *
	 * @return string
	 */
	public function getUsername()
	{
		return $this->getUser()->username;
	}

	/**
	 * Returns whether the user is authenticated or not.
	 *
	 * @return bool true if the token has been authenticated, false otherwise
	 */
	public function isAuthenticated()
	{
		// @todo this checks whether the token is valid
		return Authorizer::validateAccessToken(false, $this->serialize());
	}

	/**
	 * Sets the authenticated flag.
	 *
	 * @param bool $isAuthenticated The authenticated flag
	 */
	public function setAuthenticated($isAuthenticated)
	{
		// TODO: Implement setAuthenticated() method.
	}

	/**
	 * Removes sensitive information from the token.
	 */
	public function eraseCredentials()
	{
		$this->expire();
	}

	/**
	 * Returns the token attributes.
	 *
	 * @return array The token attributes
	 */
	public function getAttributes()
	{
		// TODO: Implement getAttributes() method.
	}

	/**
	 * Sets the token attributes.
	 *
	 * @param array $attributes The token attributes
	 */
	public function setAttributes(array $attributes)
	{
		// TODO: Implement setAttributes() method.
	}

	/**
	 * Returns true if the attribute exists.
	 *
	 * @param string $name The attribute name
	 *
	 * @return bool true if the attribute exists, false otherwise
	 */
	public function hasAttribute($name)
	{
		// TODO: Implement hasAttribute() method.
	}

	/**
	 * Returns an attribute value.
	 *
	 * @param string $name The attribute name
	 *
	 * @return mixed The attribute value
	 *
	 * @throws \InvalidArgumentException When attribute doesn't exist for this token
	 */
	public function getAttribute($name)
	{
		// TODO: Implement getAttribute() method.
	}

	/**
	 * Sets an attribute.
	 *
	 * @param string $name  The attribute name
	 * @param mixed  $value The attribute value
	 */
	public function setAttribute($name, $value)
	{
		// TODO: Implement setAttribute() method.
	}
}
