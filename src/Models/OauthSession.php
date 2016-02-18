<?php

namespace Fuzz\Auth\Models;

use Illuminate\Database\Eloquent\Model;

class OauthSession extends Model
{
	/**
	 * Clients relationship
	 *
	 * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
	 */
	public function clients()
	{
		return $this->belongsTo(OauthClient::class);
	}
}
