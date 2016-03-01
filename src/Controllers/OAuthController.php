<?php

namespace Fuzz\Auth\Controllers;

use Illuminate\Routing\Controller;
use Illuminate\Contracts\Foundation\Application;
use Symfony\Component\HttpFoundation\JsonResponse;

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
		return new JsonResponse($app['oauth2-server.authorizer']->issueAccessToken());
	}
}
