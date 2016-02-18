<?php

namespace Fuzz\Auth\Models;

use League\OAuth2\Server\AbstractServer;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Storage\ScopeInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;

class OauthScope extends ScopeEntity implements RoleInterface
{
	public $incrementing = false;

	public $id;
	public $description;

	private $scope_entity;

	public function __construct(AbstractServer $server, ScopeInterface $scope_entity)
	{
		parent::__construct($server);

		$this->scope_entity = $scope_entity;
		$this->id = $scope_entity->id;
		$this->description = $scope_entity->description;
	}

	/**
	 * Returns the role.
	 *
	 * This method returns a string representation whenever possible.
	 *
	 * When the role cannot be represented with sufficient precision by a
	 * string, it should return null.
	 *
	 * @return string|null A string representation of the role, or null
	 */
	public function getRole()
	{
		return $this->id;
	}
}
