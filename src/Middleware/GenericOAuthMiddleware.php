<?php

namespace Fuzz\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use League\OAuth2\Server\Exception\InvalidRequestException;
use LucaDegasperi\OAuth2Server\Authorizer;

/**
 * Class GenericOAuthMiddleware
 *
 * GenericOAuthMiddleware is a middleware for routes that accept both a user and client token.
 *
 * @package Fuzz\Auth\Middleware
 */
class GenericOAuthMiddleware
{
	/**
	 * The Authorizer instance.
	 *
	 * @var \LucaDegasperi\OAuth2Server\Authorizer
	 */
	protected $authorizer;

	/**
	 * Whether or not to check the http headers only for an access token.
	 *
	 * @var bool
	 */
	protected $httpHeadersOnly = false;

	/**
	 * Create a new oauth middleware instance.
	 *
	 * @param \LucaDegasperi\OAuth2Server\Authorizer $authorizer
	 * @param bool $httpHeadersOnly
	 */
	public function __construct(Authorizer $authorizer, $httpHeadersOnly = false)
	{
		$this->authorizer      = $authorizer;
		$this->httpHeadersOnly = $httpHeadersOnly;
	}

	/**
	 * Handle an incoming request.
	 *
	 * @param \Illuminate\Http\Request $request
	 * @param \Closure|Closure         $next
	 *
	 * @param null                     $guard
	 *
	 * @return mixed
	 * @throws \League\OAuth2\Server\Exception\InvalidRequestException
	 */
	public function handle(Request $request, Closure $next, $guard = null)
	{
		$this->authorizer->setRequest($request);

		$this->authorizer->validateAccessToken($this->httpHeadersOnly);

		if ($this->authorizer->getResourceOwnerType() !== 'user') {
			$this->initUser($request, $guard);
		}

		return $next($request);
	}

	/**
	 * Init the user in the Auth abstraction
	 *
	 * @param \Illuminate\Http\Request $request
	 * @param string|null              $guard
	 *
	 * @throws \League\OAuth2\Server\Exception\InvalidRequestException
	 */
	public function initUser(Request $request, string $guard = null)
	{
		if (is_null($guard)) {
			throw new \LogicException(self::class . ' called with no guard defined.');
		}

		// Attempt to resolve the application user, throws \League\OAuth2\Server\Exception\AccessDeniedException
		// if the token is invalid, or \League\OAuth2\Server\Exception\InvalidRequestException if the token
		// is missing
		$user = Auth::guard($guard)->user();

		// If above still resulted in a null user throw an error
		if (is_null($user)) {
			throw new InvalidRequestException('access token');
		}
	}
}
