<?php

namespace Fuzz\Auth\Tests\Policies;

use Fuzz\Auth\Models\AgentInterface;
use Fuzz\Auth\Policies\RepositoryModelPolicy;
use Fuzz\Auth\Tests\Models\User;
use Fuzz\MagicBox\Contracts\Repository;
use Illuminate\Database\Eloquent\Model;

class SimplePostPolicy extends RepositoryModelPolicy
{
	/**
	 * Determine if the user can access an index of the repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function index(Repository $repository)
	{
		return $this->requestHasOneOfScopes('user', 'admin');
	}

	/**
	 * Determine if the user can show this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function show(Repository $repository)
	{
		return $this->requestHasOneOfScopes('user', 'admin');
	}

	/**
	 * Determine if the user can update this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function update(Repository $repository)
	{
		return $this->requestHasOneOfScopes('admin');
	}

	/**
	 * Determine if the user can store this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function store(Repository $repository)
	{
		return $this->requestHasOneOfScopes('admin');
	}

	/**
	 * Determine if the user can destroy this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function destroy(Repository $repository)
	{
		return $this->requestHasOneOfScopes('admin');
	}

	/**
	 * Determine if this user is an owner of this object
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @return bool
	 */
	public function isObjectOwner(Repository $repository, Model $object)
	{
		$user = User::whereUsername('aNewTestUser')->first();
		return ($object->user_id === $user->id) || $this->isObjectMaster($repository, $repository->read());
	}

	/**
	 * Determine if this user is a master of this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @return bool
	 */
	public function isObjectMaster(Repository $repository, Model $object)
	{
		return $this->requestHasOneOfScopes('admin');
	}

	/**
	 * Determine if this user is a master of this collection repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function isCollectionMaster(Repository $repository)
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
		// TODO: Implement getFilters() method.
	}

	/**
	 * Determine if the user can update this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @param \Illuminate\Database\Eloquent\Model $parent
	 * @param array                               $input
	 * @return bool
	 */
	public function updateNested(Repository $repository, Model $object, Model $parent, array &$input)
	{
		// TODO: Implement updateNested() method.
	}

	/**
	 * Determine if the user can store this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository      $repository
	 * @param \Illuminate\Database\Eloquent\Model|null $object
	 * @param \Illuminate\Database\Eloquent\Model      $parent
	 * @param array                                    $input
	 * @return bool
	 */
	public function storeNested(Repository $repository, Model $object = null, Model $parent = null, array &$input)
	{
		// TODO: Implement storeNested() method.
	}

	/**
	 * Determine if this request can be unpaginated
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function unpaginatedIndex(Repository $repository)
	{
		// TODO: Implement unpaginatedIndex() method.
	}
}
