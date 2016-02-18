<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Core\Authorization\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * RoleVoter votes if any attribute starts with a given prefix.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class OAuthScopeVoter extends RoleVoter implements VoterInterface
{
	/**
	 * Role prefix
	 *
	 * @var string
	 */
	private $prefix;

	/**
	 * Constructor.
	 *
	 * @param string $prefix The role prefix
	 */
	public function __construct($prefix = '')
	{
		$this->prefix = $prefix;
	}

	/**
	 * {@inheritdoc}
	 */
	public function vote(TokenInterface $token, $subject, array $attributes)
	{
		$roles = $this->extractRoles($token);

		// Require all scopes to be present before granting access
		// expanded so we can apply different combinations of scopes
		foreach ($attributes as $attribute) {
			if (is_array($attribute)) {
				$has_roles = array_intersect($attribute, $roles);

				if (count($has_roles) === count($attribute)) {
					return VoterInterface::ACCESS_GRANTED;
				}
			} else {
				if (in_array($attribute, $roles)) {
					return VoterInterface::ACCESS_GRANTED;
				}
			}
		}

		return VoterInterface::ACCESS_DENIED;
	}

	protected function extractRoles(TokenInterface $token)
	{
		return $token->getRoles();
	}
}
