<?php

namespace App\Http\Middleware;

use Closure;

class AcceptsJson
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if($request->header('Accept') !== '*/*' && !$request->wantsJson()) {
            return response()->json('Not Acceptable', 406);
        }
        return $next($request);
    }
}
