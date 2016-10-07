<?php

namespace Fuzz\Auth\Tests\Exceptions;

use Exception;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;

class Handler extends ExceptionHandler
{
    /**
     * Convert an authentication exception into an unauthenticated response.
     *
     * @param  \Illuminate\Http\Request                 $request
     * @param  \Illuminate\Auth\AuthenticationException $e
     * @return \Symfony\Component\HttpFoundation\Response
     * @throws \Illuminate\Auth\AuthenticationException
     */
    protected function unauthenticated($request, AuthenticationException $e)
    {
       throw $e;
    }

    /**
     * Report or log an exception.
     *
     * This is a great spot to send exceptions to Sentry, Bugsnag, etc.
     *
     * @param  \Exception $e
     *
     * @throws \Exception
     */
    public function report(Exception $e)
    {
        throw $e;
    }

    /**
     * Render an exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Exception               $e
     * @return \Illuminate\Http\Response
     * @throws \Exception
     */
    public function render($request, Exception $e)
    {
        throw $e;
    }
}
