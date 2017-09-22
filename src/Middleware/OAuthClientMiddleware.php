<?php

namespace Fuzz\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use League\OAuth2\Server\Exception\AccessDeniedException;
use LucaDegasperi\OAuth2Server\Authorizer;

/**
 * Class OAuthClientMiddleware
 *
 * OAuthClientMiddleware is a middleware for routes that accept only a client token.
 *
 * @package Fuzz\Auth\Middleware
 */
class OAuthClientMiddleware
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
		$this->authorizer = $authorizer;
		$this->httpHeadersOnly = $httpHeadersOnly;
	}

	/**
	 * Handle an incoming request.
	 *
	 * @param \Illuminate\Http\Request $request
	 * @param \Closure|Closure $next
	 *
	 * @throws \League\OAuth2\Server\Exception\AccessDeniedException
	 *
	 * @return mixed
	 */
	public function handle(Request $request, Closure $next)
	{
		$this->authorizer->setRequest($request);

		$this->authorizer->validateAccessToken($this->httpHeadersOnly);

		if ($this->authorizer->getResourceOwnerType() !== 'client') {
			throw new AccessDeniedException();
		}

		return $next($request);
	}
}
