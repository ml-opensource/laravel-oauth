<?php

namespace Fuzz\Auth\Policies;

use Fuzz\Auth\Models\Traits\ChecksScopes;
use Fuzz\MagicBox\Contracts\Repository;

abstract class RepositoryModelPolicy implements RepositoryModelPolicyInterface
{
	use ChecksScopes;

	/**
	 * Merge new filters with the existing repository filters
	 *
	 * @param array                               $filters
	 * @param \Fuzz\MagicBox\Contracts\Repository $repository
	 * @return void
	 */
	public function applyRepositoryFilters(array $filters, Repository $repository)
	{
		$repository->setFilters(array_merge($repository->getFilters(), $filters));
	}

	/**
	 * Test whether the current request has the required set of scopes.
	 *
	 * Scopes passed as an array in one argument are all required. Of scopes that are passed as separate arguments,
	 * only one set is required.
	 *
	 * $args = ['IAmRequired', 'MeToo'], ['orUs', 'andUsToo']
	 *
	 * @return bool
	 */
	public function requestHasOneOfScopes()
	{
		$scopes = func_get_args();

		return call_user_func_array([$this, 'hasOneOfScopes'], $scopes);
	}

	/**
	 * Find a query filter (if any) for this scope
	 *
	 * @param string $scope
	 * @return \Closure|null
	 */
	public function getScopeFilter($scope)
	{
		$filters = $this->getFilters();

		return isset($filters[$scope]) ? $filters[$scope] : null;
	}

	/**
	 * Find a query filter (if any) for this scope
	 *
	 * @return array
	 */
	abstract public function getFilters();
}
