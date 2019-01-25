<?php

// Redirect to APP_URL
$router->get('/', function() {
	return redirect(env('APP_URL'), 301);
});

