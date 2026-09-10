<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$secret_key = "SPORTO_SECRET_KEY_2026_CHANGE_THIS";

$issuer = "sporto_api";

$access_token_expiry = 3600;

$refresh_token_expiry = 604800;

// JWT configuration used by the API
define('JWT_SECRET', $secret_key);
define('JWT_ISSUER', $issuer);

?>