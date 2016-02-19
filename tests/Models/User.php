<?php

namespace Fuzz\Auth\Tests\Models;

use Fuzz\Auth\Models\AgentInterface;
use Fuzz\Auth\Models\OauthScope;
use Fuzz\Auth\Models\Traits\PasswordableTrait;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class User extends Model implements AgentInterface, Authenticatable
{
	use SoftDeletes, PasswordableTrait;

	/**
	 * @var string
	 */
	protected $table = 'users';

	/**
	 * @var array
	 */
	protected $fillable = ['username', 'password', 'email'];

	/**
	 * @return \Illuminate\Database\Eloquent\Relations\HasMany
	 */
	public function posts()
	{
		return $this->hasMany('Fuzz\MagicBox\Tests\Models\Post');
	}

	/**
	 * @return \Illuminate\Database\Eloquent\Relations\HasOne
	 */
	public function profile()
	{
		return $this->hasOne('Fuzz\MagicBox\Tests\Models\Profile');
	}

	/**
	 * For unit testing purposes
	 *
	 * @return array
	 */
	public function getFillable()
	{
		return $this->fillable;
	}

	/**
	 * For unit testing purposes
	 *
	 * @param array $fillable
	 * @return $this
	 */
	public function setFillable(array $fillable)
	{
		$this->fillable = $fillable;

		return $this;
	}

	/**
	 * Determine whether this agent has access to certain scopes
	 *
	 * NOTE: not scopes that belong to the request token
	 *
	 * @param array $scopes
	 * @return array
	 */
	public function hasAccessToScopes(array $scopes)
	{
		// @todo this should check against the user's access to scopes, not the requests access to scopes
		return $this->hasOneOfScopes($scopes);
	}

	/**
	 * Allow the agent access to an array of scopes
	 *
	 * @param array $scopes
	 * @return array
	 */
	public function allowAccessToScopes(array $scopes)
	{
		// @todo simplified, there would be some restrictions here
		$this->scopes()->attach($scopes);
	}

	/**
	 * Scope relationship
	 *
	 * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
	 */
	public function scopes()
	{
		return $this->belongsToMany(OauthScope::class);
	}

	/**
	 * Get the name of the unique identifier for the user.
	 *
	 * @return string
	 */
	public function getAuthIdentifierName()
	{
		return 'id';
	}

	/**
	 * Get the unique identifier for the user.
	 *
	 * @return mixed
	 */
	public function getAuthIdentifier()
	{
		return $this->id;
	}

	/**
	 * Get the password for the user.
	 *
	 * @return string
	 */
	public function getAuthPassword()
	{
		return $this->password;
	}

	/**
	 * Get the token value for the "remember me" session.
	 *
	 * @return string
	 */
	public function getRememberToken()
	{
		// Do nothing
	}

	/**
	 * Set the token value for the "remember me" session.
	 *
	 * @param  string $value
	 * @return void
	 */
	public function setRememberToken($value)
	{
		// Do nothing
	}

	/**
	 * Get the column name for the "remember me" token.
	 *
	 * @return string
	 */
	public function getRememberTokenName()
	{
		// Do nothing
	}
}
