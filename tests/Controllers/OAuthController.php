<?php

namespace Fuzz\Auth\Tests\Controllers;

use Illuminate\Contracts\Foundation\Application;

class OAuthController extends Controller
{
	/**
	 * Issue an access token.
	 *
	 * @param \Illuminate\Contracts\Foundation\Application $app
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function issueAccessToken(Application $app)
	{
		return response()->json(($app['oauth2-server.authorizer']->issueAccessToken()));
	}
}
