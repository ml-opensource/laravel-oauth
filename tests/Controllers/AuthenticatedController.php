<?php

namespace Fuzz\Auth\Tests\Controllers;

class AuthenticatedController extends Controller
{
	/**
	 * An authenticated route
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function authedRoute()
	{
		$status = 'Success';
		return response()->json(['status' => $status]);
	}

	/**
	 * An authenticated route
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function notAuthedRoute()
	{
		$status = 'Success';
		return response()->json(['status' => $status]);
	}
}
