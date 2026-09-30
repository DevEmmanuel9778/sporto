<?php

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Max-Age: 86400');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/config/jwt.php';
require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function response(
    bool $status,
    string $message,
    $data = null,
    int $code = 200
): never {
    http_response_code($code);

    $output = [
        'status' => $status,
        'message' => $message,
    ];

    if ($data !== null) {
        $output['data'] = $data;
    }

    echo json_encode(
        $output,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES |
        JSON_INVALID_UTF8_SUBSTITUTE
    );

    exit;
}

function getAuthorizationHeader(): string
{
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        return trim((string) $_SERVER['HTTP_AUTHORIZATION']);
    }

    if (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
        return trim((string) $_SERVER['REDIRECT_HTTP_AUTHORIZATION']);
    }

    if (function_exists('apache_request_headers')) {
        $headers = apache_request_headers();

        if (is_array($headers)) {
            foreach ($headers as $name => $value) {
                if (strtolower((string) $name) === 'authorization') {
                    return trim((string) $value);
                }
            }
        }
    }

    if (function_exists('getallheaders')) {
        $headers = getallheaders();

        if (is_array($headers)) {
            foreach ($headers as $name => $value) {
                if (strtolower((string) $name) === 'authorization') {
                    return trim((string) $value);
                }
            }
        }
    }

    return '';
}

function authenticateAdmin(): array
{
    global $secret_key;

    $header = getAuthorizationHeader();

    if ($header === '') {
        response(
            false,
            'Authorization token is required',
            null,
            401
        );
    }

    if (!preg_match('/^Bearer\s+(.+)$/i', $header, $matches)) {
        response(
            false,
            'Invalid Authorization header',
            null,
            401
        );
    }

    $token = trim($matches[1]);

    if ($token === '') {
        response(
            false,
            'Authorization token is required',
            null,
            401
        );
    }

    try {
        $payload = (array) JWT::decode(
            $token,
            new Key($secret_key, 'HS256')
        );
    } catch (Throwable $e) {
        response(
            false,
            'Invalid or expired token',
            null,
            401
        );
    }

    if (($payload['iss'] ?? null) !== 'sporto-api') {
        response(
            false,
            'Invalid token issuer',
            null,
            401
        );
    }

    if (($payload['type'] ?? null) !== 'access') {
        response(
            false,
            'Invalid access token',
            null,
            401
        );
    }

    $role = strtolower(
        (string) ($payload['role'] ?? '')
    );

    if ($role !== 'admin') {
        response(
            false,
            'Access denied',
            null,
            403
        );
    }

    return $payload;
}

set_exception_handler(
    function (Throwable $e) {
        error_log(
            'Sporto User API Error: ' .
            $e->getMessage()
        );

        response(
            false,
            'Server error',
            null,
            500
        );
    }
);

if (
    !isset($con) ||
    !($con instanceof mysqli) ||
    $con->connect_error
) {
    response(
        false,
        'Database connection failed',
        null,
        500
    );
}

$method = strtoupper(
    $_SERVER['REQUEST_METHOD'] ?? ''
);

if ($method !== 'GET') {
    header('Allow: GET, OPTIONS');

    response(
        false,
        'Only GET method is allowed',
        null,
        405
    );
}

authenticateAdmin();

$stmt = $con->prepare(
    "SELECT
        id,
        name,
        email,
        phone,
        role
     FROM users
     WHERE role = 'user'
     ORDER BY id DESC"
);

if (!$stmt) {
    response(
        false,
        'Failed to prepare users query',
        null,
        500
    );
}

if (!$stmt->execute()) {
    $error = $stmt->error;
    $stmt->close();

    error_log(
        'Sporto User API Query Error: ' .
        $error
    );

    response(
        false,
        'Failed to fetch users',
        null,
        500
    );
}

$result = $stmt->get_result();

$users = [];

while ($row = $result->fetch_assoc()) {
    $users[] = [
        'id' => (int) $row['id'],
        'name' => (string) $row['name'],
        'email' => (string) $row['email'],
        'phone' => $row['phone'] !== null
            ? (string) $row['phone']
            : null,
        'role' => (string) $row['role'],
    ];
}

$stmt->close();

response(
    true,
    'Users fetched successfully',
    [
        'users' => $users,
        'count' => count($users),
    ]
);
?>
