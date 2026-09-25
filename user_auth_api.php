
<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

require_once __DIR__ . '/vendor/autoload.php';

// ============================================================
// RESPONSE
// ============================================================

function authResponse(int $code, array $data): never
{
    http_response_code($code);
    echo json_encode(
        $data,
        JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
    );
    exit;
}

// ============================================================
// DATABASE - AIVEN
// ============================================================

function authDb(): mysqli
{
    $host = getenv('DB_HOST');
    $port = (int) (getenv('DB_PORT') ?: 3306);
    $user = getenv('DB_USER');
    $password = getenv('DB_PASSWORD');
    $database = getenv('DB_NAME') ?: 'defaultdb';

    if (!$host || !$user || $password === false) {
        authResponse(500, [
            'status' => false,
            'message' => 'Database configuration missing'
        ]);
    }

    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    $db = mysqli_init();

    $ca = getenv('DB_SSL_CA');

    if ($ca) {
        $db->ssl_set(null, null, $ca, null, null);
    }

    $db->real_connect(
        $host,
        $user,
        $password,
        $database,
        $port,
        null,
        MYSQLI_CLIENT_SSL
    );

    $db->set_charset('utf8mb4');
    $db->query("SET time_zone = '+00:00'");

    return $db;
}

// ============================================================
// JWT
// ============================================================

function authSecret(): string
{
    $secret = getenv('JWT_SECRET');

    if (!$secret) {
        authResponse(500, [
            'status' => false,
            'message' => 'JWT_SECRET is not configured'
        ]);
    }

    return $secret;
}

function createUserToken(
    int $userId,
    string $type,
    int $lifetime
): string {
    $now = time();

    return JWT::encode([
        'iss' => 'sporto_api',
        'sub' => (string) $userId,
        'id' => $userId,
        'role' => 'user',
        'type' => $type,
        'iat' => $now,
        'nbf' => $now,
        'exp' => $now + $lifetime,
        'jti' => bin2hex(random_bytes(16))
    ], authSecret(), 'HS256');
}

function verifyUserToken(
    string $token,
    string $expectedType
): object {
    try {
        $payload = JWT::decode(
            $token,
            new Key(authSecret(), 'HS256')
        );

        if (
            ($payload->role ?? null) !== 'user' ||
            ($payload->type ?? null) !== $expectedType ||
            (int) ($payload->sub ?? 0) < 1
        ) {
            authResponse(401, [
                'status' => false,
                'message' => 'Invalid token'
            ]);
        }

        return $payload;

    } catch (Throwable $e) {
        authResponse(401, [
            'status' => false,
            'message' => 'Invalid or expired token'
        ]);
    }
}

function getBearerToken(): string
{
    $header =
        $_SERVER['HTTP_AUTHORIZATION']
        ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
        ?? '';

    if (!$header && function_exists('getallheaders')) {
        foreach (getallheaders() as $key => $value) {
            if (strcasecmp($key, 'Authorization') === 0) {
                $header = $value;
                break;
            }
        }
    }

    if (!preg_match('/^Bearer\s+(\S+)$/i', trim($header), $matches)) {
        authResponse(401, [
            'status' => false,
            'message' => 'Bearer token required'
        ]);
    }

    return $matches[1];
}

// ============================================================
// ISSUE ACCESS + REFRESH TOKENS
// ============================================================

function issueUserTokens(
    mysqli $db,
    int $userId
): array {
    $accessLifetime = 900;
    $refreshLifetime = 604800;

    $accessToken = createUserToken(
        $userId,
        'access',
        $accessLifetime
    );

    $refreshToken = createUserToken(
        $userId,
        'refresh',
        $refreshLifetime
    );

    $tokenHash = hash('sha256', $refreshToken);

    $expiresAt = gmdate(
        'Y-m-d H:i:s',
        time() + $refreshLifetime
    );

    $stmt = $db->prepare(
        'INSERT INTO user_refresh_tokens
         (user_id, token_hash, expires_at)
         VALUES (?, ?, ?)'
    );

    $stmt->bind_param(
        'iss',
        $userId,
        $tokenHash,
        $expiresAt
    );

    $stmt->execute();

    return [
        'access_token' => $accessToken,
        'refresh_token' => $refreshToken,
        'token_type' => 'Bearer',
        'expires_in' => $accessLifetime
    ];
}

// ============================================================
// REQUEST
// ============================================================

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');

    authResponse(405, [
        'status' => false,
        'message' => 'POST method required'
    ]);
}

$body = json_decode(
    file_get_contents('php://input'),
    true
);

if (!is_array($body)) {
    authResponse(400, [
        'status' => false,
        'message' => 'Valid JSON body required'
    ]);
}

$action = strtolower(
    trim((string) ($_GET['action'] ?? ''))
);

// ============================================================
// USER AUTH ACTIONS
// ============================================================

try {

    switch ($action) {

        // ====================================================
        // USER REGISTER
        // ====================================================

        case 'register':

            $name = trim((string) ($body['name'] ?? ''));
            $email = strtolower(
                trim((string) ($body['email'] ?? ''))
            );
            $phone = trim((string) ($body['phone'] ?? ''));
            $password = (string) ($body['password'] ?? '');

            if (
                mb_strlen($name) < 2 ||
                mb_strlen($name) > 100 ||
                !filter_var($email, FILTER_VALIDATE_EMAIL) ||
                strlen($email) > 191 ||
                strlen($phone) > 20 ||
                strlen($password) < 8 ||
                strlen($password) > 72
            ) {
                authResponse(422, [
                    'status' => false,
                    'message' => 'Invalid registration details'
                ]);
            }

            $db = authDb();

            $stmt = $db->prepare(
                'SELECT id FROM users
                 WHERE email = ?
                 LIMIT 1'
            );

            $stmt->bind_param('s', $email);
            $stmt->execute();

            if ($stmt->get_result()->fetch_assoc()) {
                authResponse(409, [
                    'status' => false,
                    'message' => 'Email already registered'
                ]);
            }

            $passwordHash = password_hash(
                $password,
                PASSWORD_DEFAULT
            );

            $db->begin_transaction();

            $stmt = $db->prepare(
                "INSERT INTO users
                 (name, email, phone, password, role)
                 VALUES (?, ?, ?, ?, 'user')"
            );

            $stmt->bind_param(
                'ssss',
                $name,
                $email,
                $phone,
                $passwordHash
            );

            $stmt->execute();

            $userId = (int) $db->insert_id;

            $tokens = issueUserTokens($db, $userId);

            $db->commit();

            authResponse(201, [
                'status' => true,
                'message' => 'Registration successful',
                'data' => array_merge([
                    'id' => $userId,
                    'name' => $name,
                    'email' => $email,
                    'phone' => $phone,
                    'role' => 'user'
                ], $tokens),
                ...$tokens
            ]);

        // ====================================================
        // USER LOGIN
        // ====================================================

        case 'login':

            $email = strtolower(
                trim((string) ($body['email'] ?? ''))
            );

            $password = (string) ($body['password'] ?? '');

            if (
                !filter_var($email, FILTER_VALIDATE_EMAIL) ||
                $password === ''
            ) {
                authResponse(422, [
                    'status' => false,
                    'message' => 'Email and password required'
                ]);
            }

            $db = authDb();

            $stmt = $db->prepare(
                "SELECT id, name, email, phone, password
                 FROM users
                 WHERE email = ?
                 AND role = 'user'
                 LIMIT 1"
            );

            $stmt->bind_param('s', $email);
            $stmt->execute();

            $user = $stmt->get_result()->fetch_assoc();

            if (
                !$user ||
                !password_verify($password, $user['password'])
            ) {
                authResponse(401, [
                    'status' => false,
                    'message' => 'Invalid email or password'
                ]);
            }

            $tokens = issueUserTokens(
                $db,
                (int) $user['id']
            );

            authResponse(200, [
                'status' => true,
                'message' => 'Login successful',
                'data' => array_merge([
                    'id' => (int) $user['id'],
                    'name' => $user['name'],
                    'email' => $user['email'],
                    'phone' => $user['phone'],
                    'role' => 'user'
                ], $tokens),
                ...$tokens
            ]);

        // ====================================================
        // REFRESH TOKEN
        // ====================================================

        case 'refresh':

            $refreshToken = (string) (
                $body['refresh_token'] ?? ''
            );

            if ($refreshToken === '') {
                authResponse(422, [
                    'status' => false,
                    'message' => 'Refresh token required'
                ]);
            }

            $claims = verifyUserToken(
                $refreshToken,
                'refresh'
            );

            $userId = (int) $claims->sub;

            $tokenHash = hash(
                'sha256',
                $refreshToken
            );

            $db = authDb();
            $db->begin_transaction();

            $stmt = $db->prepare(
                'SELECT id
                 FROM user_refresh_tokens
                 WHERE user_id = ?
                 AND token_hash = ?
                 AND revoked_at IS NULL
                 AND expires_at > UTC_TIMESTAMP()
                 FOR UPDATE'
            );

            $stmt->bind_param(
                'is',
                $userId,
                $tokenHash
            );

            $stmt->execute();

            $storedToken = $stmt->get_result()->fetch_assoc();

            if (!$storedToken) {
                $db->rollback();

                authResponse(401, [
                    'status' => false,
                    'message' => 'Refresh token revoked or expired'
                ]);
            }

            $stmt = $db->prepare(
                'UPDATE user_refresh_tokens
                 SET revoked_at = UTC_TIMESTAMP()
                 WHERE id = ?'
            );

            $storedId = (int) $storedToken['id'];

            $stmt->bind_param('i', $storedId);
            $stmt->execute();

            $tokens = issueUserTokens($db, $userId);

            $db->commit();

            authResponse(200, [
                'status' => true,
                'message' => 'Token refreshed',
                'data' => $tokens,
                ...$tokens
            ]);

        // ====================================================
        // USER LOGOUT
        // ====================================================

        case 'logout':

            $accessClaims = verifyUserToken(
                getBearerToken(),
                'access'
            );

            $refreshToken = (string) (
                $body['refresh_token'] ?? ''
            );

            if ($refreshToken === '') {
                authResponse(422, [
                    'status' => false,
                    'message' => 'Refresh token required'
                ]);
            }

            $refreshClaims = verifyUserToken(
                $refreshToken,
                'refresh'
            );

            if (
                (int) $accessClaims->sub !==
                (int) $refreshClaims->sub
            ) {
                authResponse(403, [
                    'status' => false,
                    'message' => 'Token user mismatch'
                ]);
            }

            $db = authDb();

            $userId = (int) $accessClaims->sub;

            $tokenHash = hash(
                'sha256',
                $refreshToken
            );

            $stmt = $db->prepare(
                'UPDATE user_refresh_tokens
                 SET revoked_at = UTC_TIMESTAMP()
                 WHERE user_id = ?
                 AND token_hash = ?
                 AND revoked_at IS NULL'
            );

            $stmt->bind_param(
                'is',
                $userId,
                $tokenHash
            );

            $stmt->execute();

            authResponse(200, [
                'status' => true,
                'message' => 'Logged out successfully'
            ]);

        default:

            authResponse(404, [
                'status' => false,
                'message' => 'Unknown action'
            ]);
    }

} catch (mysqli_sql_exception $e) {

    if (isset($db)) {
        try {
            $db->rollback();
        } catch (Throwable $ignored) {
        }
    }

    if (
        (int) $e->getCode() === 1062 &&
        $action === 'register'
    ) {
        authResponse(409, [
            'status' => false,
            'message' => 'Email already registered'
        ]);
    }

    error_log(
        'Sporto User Auth DB Error: ' . $e->getMessage()
    );

    authResponse(500, [
        'status' => false,
        'message' => 'Database request failed'
    ]);

} catch (Throwable $e) {

    if (isset($db)) {
        try {
            $db->rollback();
        } catch (Throwable $ignored) {
        }
    }

    error_log(
        'Sporto User Auth Error: ' . $e->getMessage()
    );

    authResponse(500, [
        'status' => false,
        'message' => 'Authentication request failed'
    ]);
}