<?php

namespace Fuzz\Auth\Policies;

trait ChecksGatePolicies
{
	/**
	 * Policy class storage
	 *
	 * @var string
	 */
	private $policy_class;

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
	 * @return mixed
	 */
	public function policy()
	{
		return policy($this->policy_class);
	}
}
