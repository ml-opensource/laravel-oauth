<?php

namespace Fuzz\Auth\Policies;

use Fuzz\Auth\Models\AgentInterface;
use Fuzz\MagicBox\Contracts\Repository;
use Illuminate\Database\Eloquent\Model;

interface RepositoryModelPolicyInterface
{
	/**
	 * Determine if the user can access an index of the repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function index(AgentInterface $user, Repository $repository);

	/**
	 * Determine if the user can show this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @return bool
	 */
	public function show(AgentInterface $user, Repository $repository, Model $object);

	/**
	 * Determine if the user can update this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @return bool
	 */
	public function update(AgentInterface $user, Repository $repository, Model $object);

	/**
	 * Determine if the user can update this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @param \Illuminate\Database\Eloquent\Model $parent
	 * @param array                               $input
	 * @return bool
	 */
	public function updateNested(AgentInterface $user, Repository $repository, Model $object, Model $parent, array &$input);

	/**
	 * Determine if the user can store this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface         $user
	 * @param \Fuzz\MagicBox\Contracts\Repository      $repository
	 * @param \Illuminate\Database\Eloquent\Model|null $object
	 * @return bool
	 */
	public function store(AgentInterface $user, Repository $repository, Model $object = null);

	/**
	 * Determine if the user can store this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface         $user
	 * @param \Fuzz\MagicBox\Contracts\Repository      $repository
	 * @param \Illuminate\Database\Eloquent\Model|null $object
	 * @param \Illuminate\Database\Eloquent\Model      $parent
	 * @param array                                    $input
	 * @return bool
	 */
	public function storeNested(AgentInterface $user, Repository $repository, Model $object = null, Model $parent = null, array &$input);

	/**
	 * Determine if the user can destroy this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @return bool
	 */
	public function destroy(AgentInterface $user, Repository $repository, Model $object);

	/**
	 * Determine if this user is an owner of this object
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @return bool
	 */
	public function isObjectOwner(AgentInterface $user, Repository $repository, Model $object);

	/**
	 * Determine if this user is a master of this repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @return bool
	 */
	public function isObjectMaster(AgentInterface $user, Repository $repository, Model $object);

	/**
	 * Determine if this user is a master of this collection repository
	 *
	 * @param \Fuzz\Auth\Models\AgentInterface    $user
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function isCollectionMaster(AgentInterface $user, Repository $repository);
}
