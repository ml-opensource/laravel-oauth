<?php

namespace Fuzz\Auth\Tests\Policies;

use Fuzz\Auth\Models\AgentInterface;
use Fuzz\Auth\Policies\RepositoryModelPolicy;
use Fuzz\MagicBox\Contracts\Repository;
use Illuminate\Database\Eloquent\Model;

class PostPolicy extends RepositoryModelPolicy
{
	/**
	 * Determine if the user can access an index of the repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function index(AgentInterface $user, Repository $repository)
	{
		if (! $this->requestHasOneOfScopes('user', 'admin')) {
			return false;
		}

		$this->applyRepositoryFilters([$this->getScopeFilter('someFilter')], $repository);

		return true;
	}

	/**
	 * Determine if the user can show this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function show(AgentInterface $user, Repository $repository)
	{
		if (! $this->requestHasOneOfScopes('user', 'admin')) {
			return false;
		}

		$this->applyRepositoryFilters([$this->getScopeFilter('someFilter')], $repository);

		return true;
	}

	/**
	 * Determine if the user can update this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function update(AgentInterface $user, Repository $repository)
	{
		if (! $this->requestHasOneOfScopes('admin')) {
			return false;
		}

		$this->applyRepositoryFilters([$this->getScopeFilter('someFilter')], $repository);

		return true;
	}

	/**
	 * Determine if the user can store this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function store(AgentInterface $user, Repository $repository)
	{
		if (! $this->requestHasOneOfScopes('admin')) {
			return false;
		}

		$this->applyRepositoryFilters([$this->getScopeFilter('someFilter')], $repository);

		return true;
	}

	/**
	 * Determine if the user can destroy this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function destroy(AgentInterface $user, Repository $repository)
	{
		if (! $this->requestHasOneOfScopes('admin')) {
			return false;
		}

		$this->applyRepositoryFilters([$this->getScopeFilter('someFilter')], $repository);

		return true;
	}

	/**
	 * Determine if this user is an owner of this object
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @return bool
	 */
	public function isObjectOwner(AgentInterface $user, Repository $repository, Model $object)
	{
		return ($object->user_id === $user->getKey()) || $this->isObjectMaster($user, $repository, $object);
	}

	/**
	 * Determine if this user is a master of this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @return bool
	 */
	public function isObjectMaster(AgentInterface $user, Repository $repository, Model $object)
	{
		return $this->requestHasOneOfScopes('admin');
	}

	/**
	 * Determine if this user is a master of this collection repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function isCollectionMaster(AgentInterface $user, Repository $repository)
	{
		return $this->requestHasOneOfScopes('admin');
	}

	/**
	 * Find a query filter (if any) for this scope
	 *
	 * @return array
	 */
	public function getFilters()
	{
		// Doesn't matter, this is ultimately up to the implementation.
		// We only care that the filters get applied
		return [
			'someFilter' => function () {
				return 'someFilter';
			},
		];
	}
}
