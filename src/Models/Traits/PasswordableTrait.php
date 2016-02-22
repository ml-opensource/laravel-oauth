<?php

namespace Fuzz\Auth\Models\Traits;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

trait PasswordableTrait
{
	/**
	 * Attach a password to the user.
	 *
	 * @param  string $value
	 * @return void
	 */
	public function setPasswordAttribute($value)
	{
		$this->attributes['password'] = Hash::make($value);
	}

	/**
	 * Attach a password to the user.
	 *
	 * @param  string $value
	 * @return void
	 */
	public function setPasswordTokenAttribute($value)
	{
		$this->attributes['password_token'] = Hash::make($value);
	}

	/**
	 * Check if a password is valid.
	 *
	 * @param  string $password
	 * @return boolean
	 */
	public function checkPassword($password)
	{
		return Hash::check($password, $this->attributes['password']);
	}

	/**
	 * Check if a password token is valid.
	 *
	 * @param  string $password_token
	 * @return boolean
	 */
	private function checkPasswordToken($password_token)
	{
		return Hash::check($password_token, $this->attributes['password_token']);
	}

	/**
	 * Generate a new password token.
	 *
	 * @return string
	 */
	public function forgePasswordToken()
	{
		$password_token       = Str::random(128);
		$this->password_token = $password_token;

		if ($this->save()) {
			return $password_token;
		}
	}

	/**
	 * Reset password with a token.
	 *
	 * @param  string $password_token
	 * @param  string $new_password
	 * @return boolean
	 */
	public function changePassword($password_token, $new_password)
	{
		if ($this->checkPasswordToken($password_token)) {
			$this->password                     = $new_password;
			$this->attributes['password_token'] = null;
			$this->revokeSessionsForOwnerTypeAndId('user', $this->{$this->getKeyName()});

			return true;
		}

		return false;
	}
}
