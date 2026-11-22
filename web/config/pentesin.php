<?php

return [
    'runner_token' => env('PENTESIN_RUNNER_TOKEN'),
    'lease_seconds' => max(60, (int) env('PENTESIN_LEASE_SECONDS', 300)),
];
