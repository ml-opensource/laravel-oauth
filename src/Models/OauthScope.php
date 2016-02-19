<?php

namespace Fuzz\Auth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class OauthScope extends Model
{
	public $incrementing = false;

	/**
	 * User relationship
	 *
	 * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
	 */
	public function users()
	{
		return $this->belongsToMany(User::class);
	}

	/**
	 * Clients relationship
	 *
	 * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
	 */
	public function clients()
	{
		return $this->belongsToMany(OauthClient::class, 'oauth_client_scopes', 'scope_id', 'client_id');
	}

	// @todo does this belong here?
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
