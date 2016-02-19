<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AuthTables extends Migration
{
	/**
	 * Run the migrations.
	 *
	 * @return void
	 */
	public function up()
	{
		Schema::dropIfExists('users');

		Schema::create(
			'users', function (Blueprint $table) {
				$table->increments('id');
				$table->string('username')->nullable()->default('')->unique();
				$table->string('email')->nullable()->default('')->unique();
				$table->string('password')->nullable();
				$table->string('password_token', 60)->nullable();
				$table->timestamps();
				$table->softDeletes();
			}
		);

		Schema::create(
			'oauth_scope_user', function (Blueprint $table) {
			$table->increments('id');
			$table->integer('user_id')->unsigned();
			$table->string('oauth_scope_id');
		});

		Schema::table(
			'oauth_scope_user', function ($table) {
			$table->foreign('user_id')
				->references('id')->on('users')
				->onDelete('cascade');

			$table->foreign('oauth_scope_id')
				->references('id')->on('oauth_scopes')
				->onDelete('cascade');
		});
	}

	/**
	 * Reverse the migrations.
	 *
	 * @return void
	 */
	public function down()
	{
		Schema::dropIfExists('oauth_scope_user');
		Schema::dropIfExists('users');
	}
}
