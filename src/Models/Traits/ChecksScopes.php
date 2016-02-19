<?php

namespace Fuzz\Auth\Models\Traits;

use LucaDegasperi\OAuth2Server\Facades\Authorizer;

trait ChecksScopes
{
	/**
	 * Test whether the current Agent has the required set of scopes.
	 *
	 * Scopes passed as an array in one argument are all required. Of scopes that are passed as separate arguments,
	 * only one set is required.
	 *
	 * $args = [['IAmRequired', 'MeToo'], ['orUs', 'andUsToo']]
	 *
	 * @return bool
	 */
	public static function hasOneOfScopes()
	{
		$scopes = func_get_args();

		$has_required_scopes = false;
		foreach ($scopes as $required_scope_set) {
			if (! is_string($required_scope_set) && ! is_array($required_scope_set)) {
				throw new \LogicException('Invalid reference to required scopes.');
			}

			// hasScope accepts array or string.
			if (Authorizer::hasScope($required_scope_set)) {
				$has_required_scopes = true;
				break;
			}
		}

		return $has_required_scopes;
	}
}
