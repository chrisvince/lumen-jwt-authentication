<?php

// Redirect to APP_URL
$router->get('/', function() {
	return redirect(env('APP_URL'), 301);
});

$router->group(['prefix' => 'v1'], function () use ($router) {
	
	// Authentication
	$router->group(['prefix' => 'auth'], function () use ($router) {
		$router->post('login', 'AuthController@login');
		$router->post('register', 'AuthController@register');
		$router->post('refresh', 'AuthController@refresh');
		$router->post('user', 'AuthController@user');
		$router->post('logout', 'AuthController@logout');
		$router->post('deactivate', 'AuthController@deactivate');
		$router->post('restore', 'AuthController@restore');
		$router->group(['prefix' => 'password'], function () use ($router) {
			$router->post('reset-request', 'AuthController@resetPasswordRequest');
			$router->post('reset', 'AuthController@resetPassword');
		});
		$router->group(['prefix' => 'email'], function () use ($router) {
			$router->post('verify', 'AuthController@verifyEmail');
			$router->post('request-verification', 'AuthController@requestEmailVerification');
			$router->post('check-verification', 'AuthController@checkEmailVerification');
		});
	});
});
