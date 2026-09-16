<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$secretKey = getenv('JWT_SECRET');

if (!$secretKey) {
    die('JWT_SECRET environment variable is not configured');
}

$issuer = "sporto_api";

$access_token_expiry = 3600;

$refresh_token_expiry = 604800;

// JWT configuration used by the API
define('JWT_SECRET', $secretKey);
define('JWT_ISSUER', $issuer);
define('JWT_ACCESS_TOKEN_EXPIRY', $access_token_expiry);
?>