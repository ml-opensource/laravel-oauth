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
	 * @return $this
	 */
	public function setPolicyClass($policy_class)
	{
		$this->policy_class = $policy_class;
		return $this;
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
	 * @return \Fuzz\Auth\Policies\RepositoryModelPolicyInterface|mixed
	 */
	public function policy()
	{
		if (! is_null($this->policy)) {
			return $this->policy;
		}

		return $this->policy = policy($this->policy_class);
	}
}
