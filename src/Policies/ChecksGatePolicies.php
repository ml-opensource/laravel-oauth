<?php

namespace Fuzz\Auth\Policies;

trait ChecksGatePolicies
{
	/**
	 * Policy class storage
	 *
	 * @var string
	 */
	public $policy_class;

	/**
	 * Policy storage
	 *
	 * @var \Fuzz\Auth\Policies\RepositoryModelPolicyInterface|mixed
	 */
	public $policy;

	/**
	 * Set the policy class for this class
	 *
	 * @param string $policy_class
	 * @return \Fuzz\Auth\Policies\RepositoryModelPolicyInterface|mixed
	 */
	public function setPolicyClass($policy_class)
	{
		$this->policy_class = $policy_class;
		return $this->policy(true);
	}

	/**
	 * Get this class' policy class
	 *
	 * @return string
	 */
	public function getPolicyClass()
	{
		return $this->policy_class;
	}

	/**
	 * Get this class' policy
	 *
	 * @param bool $force_new
	 * @return \Fuzz\Auth\Policies\RepositoryModelPolicyInterface|mixed
	 */
	public function policy($force_new = false)
	{
		if ((! $force_new) && (! is_null($this->policy))) {
			return $this->policy;
		}

		return $this->policy = policy($this->policy_class);
	}
}
