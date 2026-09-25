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

<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// JWT secret from Render environment
$secretKey = getenv('JWT_SECRET');

if ($secretKey === false || trim($secretKey) === '') {
    http_response_code(500);

    header('Content-Type: application/json');

    echo json_encode([
        'status' => false,
        'message' => 'JWT_SECRET is not configured',
    ]);

    exit;
}

// Compatibility with existing APIs
$secret_key = $secretKey;

// JWT configuration
$issuer = 'sporto_api';

$access_token_expiry = 3600;

$refresh_token_expiry = 604800;

// Constants used by other API files
if (!defined('JWT_SECRET')) {
    define('JWT_SECRET', $secretKey);
}

if (!defined('JWT_ISSUER')) {
    define('JWT_ISSUER', $issuer);
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
// JWT configuration used by the API
define('JWT_SECRET', $secretKey);
define('JWT_ISSUER', $issuer);
define('JWT_ACCESS_TOKEN_EXPIRY', $access_token_expiry);
?>