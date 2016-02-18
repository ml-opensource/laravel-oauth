<?php

namespace Fuzz\Auth\Providers;

use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Auth;
use Fuzz\Auth\Guards\OAuthGuard;

class AuthServiceProvider extends ServiceProvider
{
    ///**
    // * The policy mappings for the application.
    // *
    // * @var array
    // */
    //protected $policies = [
    //    'Tapwiser\Model' => 'Tapwiser\Policies\ModelPolicy',
    //];

    /**
     * Register any application authentication / authorization services.
     *
     * @param  \Illuminate\Contracts\Auth\Access\Gate  $gate
     * @return void
     */
    public function boot(GateContract $gate)
    {
        $this->registerPolicies($gate);

	    // Register an OAuthGuard to be used for our
        Auth::extend(OAuthGuard::class, function($app, $name, array $config) {
	        return new OAuthGuard(Auth::createUserProvider($config['provider']));
        });
    }
}
