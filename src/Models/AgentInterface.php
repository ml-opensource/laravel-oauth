<?php

namespace Fuzz\Auth\Models;

interface AgentInterface
{
	/**
	 * Find the agent's primary key value
	 *
	 * @return mixed
	 */
	public function getKey();

	/**
	 * Get the primary key for the model.
	 *
	 * @return string
	 */
	public function getKeyName();

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
}
