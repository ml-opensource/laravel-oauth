<?php

namespace Fuzz\Auth\Models;

use Illuminate\Database\Eloquent\Model;

class OauthClient extends Model
{
	public $incrementing = false;

	/**
	 * User relationship
	 *
	 * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
	 */
	public function scopes()
	{
		return $this->belongsToMany(OauthScope::class, 'oauth_client_scopes', 'client_id', 'scope_id');
	}
}
