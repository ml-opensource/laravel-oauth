<?php

namespace Fuzz\Auth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class OauthScope extends Model
{
	public $incrementing = false;

	/**
	 * Clients relationship
	 *
	 * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
	 */
	public function clients()
	{
		return $this->belongsToMany(OauthClient::class, 'oauth_client_scopes', 'scope_id', 'client_id');
	}

	/**
	 * Provide a convenience method for attaching scopes to a user
	 *
	 * @param \Illuminate\Database\Eloquent\Model $user
	 * @param array                               $scopes
	 */
	public static function attachToUser(Model $user, array $scopes)
	{
		$attach_scopes = [];

		foreach ($scopes as $scope) {
			$attach_scopes[] = [
				'user_id' => $user->id,
				'oauth_scope_id' => $scope,
			];
		}

		DB::table('oauth_scope_user')->insert($attach_scopes);
	}
}
