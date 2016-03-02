<?php

namespace Fuzz\Auth\Policies;

use Fuzz\MagicBox\Contracts\Repository;
use Illuminate\Database\Eloquent\Model;

interface RepositoryModelPolicyInterface
{
	/**
	 * Determine if this request can access an index of the repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function index(Repository $repository);

	/**
	 * Determine if this request can show this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function show(Repository $repository);

	/**
	 * Determine if this request can update this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function update(Repository $repository);

	/**
	 * Determine if this request can store this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository      $repository
	 * @return bool
	 */
	public function store(Repository $repository);

	/**
	 * Determine if this request can destroy this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function destroy(Repository $repository);

	/**
	 * Determine if this request can update this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @param \Illuminate\Database\Eloquent\Model $parent
	 * @param array                               $input
	 * @return bool
	 */
	public function updateNested(Repository $repository, Model $object, Model $parent, array &$input);

	/**
	 * Determine if this request can store this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository      $repository
	 * @param \Illuminate\Database\Eloquent\Model|null $object
	 * @param \Illuminate\Database\Eloquent\Model      $parent
	 * @param array                                    $input
	 * @return bool
	 */
	public function storeNested(Repository $repository, Model $object = null, Model $parent = null, array &$input);

	/**
	 * Determine if this user is an owner of this object
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @return bool
	 */
	public function isObjectOwner(Repository $repository, Model $object);

	/**
	 * Determine if this user is a master of this repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @param \Illuminate\Database\Eloquent\Model $object
	 * @return bool
	 */
	public function isObjectMaster(Repository $repository, Model $object);

	/**
	 * Determine if this user is a master of this collection repository
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function isCollectionMaster(Repository $repository);

	/**
	 * Determine if this request can be unpaginated
	 *
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return bool
	 */
	public function unpaginatedIndex(Repository $repository);
}
