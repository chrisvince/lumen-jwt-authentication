<?php

// Redirect to APP_URL
Route::get('/', function() {
	return redirect(env('APP_URL'), 301);
});
