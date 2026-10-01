<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// ============================================================
// JWT SECRET
// ============================================================

// JWT secret from Render environment.
$secretKey = getenv('JWT_SECRET');

if ($secretKey === false || trim($secretKey) === '') {
    http_response_code(500);
    header('Content-Type: application/json; charset=UTF-8');

    echo json_encode([
        'status' => false,
        'message' => 'JWT_SECRET is not configured',
    ]);

    exit;
}

// Support both existing variable names.
$secret_key = $secretKey;

// ============================================================
// JWT CONFIGURATION
// ============================================================

// Keep this value identical everywhere
// JWT tokens are generated and validated.
$issuer = 'sporto-api';

// Access token expiry:
// 24 hours = 86,400 seconds.
$access_token_expiry = 86400;

$refresh_token_expiry = 8640000;

// ============================================================
// CONSTANTS
// ============================================================

if (!defined('JWT_SECRET')) {
    define(
        'JWT_SECRET',
        $secretKey
    );
}

if (!defined('JWT_ISSUER')) {
    define(
        'JWT_ISSUER',
        $issuer
    );
}

if (!defined('JWT_ACCESS_TOKEN_EXPIRY')) {
    define(
        'JWT_ACCESS_TOKEN_EXPIRY',
        $access_token_expiry
    );
}

if (!defined('JWT_REFRESH_TOKEN_EXPIRY')) {
    define(
        'JWT_REFRESH_TOKEN_EXPIRY',
        $refresh_token_expiry
    );
}