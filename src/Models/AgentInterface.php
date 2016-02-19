<?php

namespace Fuzz\Auth\Models;

interface AgentInterface
{
	/**
	 * Determine whether this agent (not request) has access to certain scopes
	 *
	 * NOTE: not scopes that belong to the request token
	 *
	 * @param array $scopes
	 * @return array
	 */
	public function hasAccessToScopes(array $scopes);

	/**
	 * Allow the agent access to an array of scopes
	 *
	 * @param array $scopes
	 * @return array
	 */
	public function allowAccessToScopes(array $scopes);

	/**
	 * Scopes relationship
	 *
	 * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
	 */
	public function scopes();

	/**
	 * Attach a password to the user.
	 *
	 * @param  string $value
	 * @return void
	 */
	public function setPasswordAttribute($value);

	/**
	 * Check if a password is valid.
	 *
	 * @param  string $password
	 * @return boolean
	 */
	public function checkPassword($password);
}
