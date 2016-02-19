<?php

namespace Fuzz\Auth\Models;

interface AgentResolverInterface
{
	/**
	 * Resolve the application agent from the request token
	 *
	 * @return \Illuminate\Database\Eloquent\Model
	 */
	public function resolveAppAgent();

	/**
	 * Revoke all sessions for the owner.
	 *
	 * Access tokens will be revoked through cascades.
	 *
	 * @todo: This should live in the OAuth2 package, but it does not currently provide a clean way
	 *      of revoking sessions and/or tokens in bulk.
	 *
	 * @param string  $owner_type
	 * @param integer $owner_id
	 */
	public static function revokeSessionsForOwnerTypeAndId($owner_type, $owner_id);
}
