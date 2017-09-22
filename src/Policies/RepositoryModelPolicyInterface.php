<?php

namespace Fuzz\Auth\Policies;

use Fuzz\MagicBox\Contracts\Repository;

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
}
