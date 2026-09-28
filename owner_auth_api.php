<?php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once __DIR__ . '/vendor/autoload.php';

const OWNER_ACCESS_LIFETIME = 24 * 60 * 60;
const OWNER_REFRESH_LIFETIME = 100 * 24 * 60 * 60;

function ownerResponse(bool $status, string $message, array $data = [], int $code = 200): never
{
    http_response_code($code);
    echo json_encode(
        array_merge(['status' => $status, 'message' => $message], $data),
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
    );
    exit;
}

function ownerSecret(): string
{
    $secret = getenv('JWT_SECRET');
    if ($secret === false || trim($secret) === '') {
        ownerResponse(false, 'JWT_SECRET is not configured', [], 500);
    }
    return $secret;
}

function ownerDb(): mysqli
{
    $host = getenv('DB_HOST');
    $port = (int) (getenv('DB_PORT') ?: 3306);
    $database = getenv('DB_NAME') ?: 'defaultdb';
    $username = getenv('DB_USER');
    $password = getenv('DB_PASSWORD');
    if (!$host || !$username || $password === false || $port <= 0) {
        ownerResponse(false, 'Database configuration missing', [], 500);
    }

    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $db = mysqli_init();
    if ($db === false) {
        throw new RuntimeException('Database initialization failed');
    }
    $ca = getenv('DB_SSL_CA');
    if ($ca) {
        $db->ssl_set(null, null, $ca, null, null);
    }
    $db->real_connect($host, $username, $password, $database, $port, null, MYSQLI_CLIENT_SSL);
    $db->set_charset('utf8mb4');
    $db->query("SET time_zone = '+00:00'");
    return $db;
}

function createOwnerToken(int $id, string $name, string $email, string $type, int $lifetime): string
{
    $now = time();
    return JWT::encode([
        'iss' => 'sporto-api',
        'sub' => (string) $id,
        'user_id' => $id,
        'name' => $name,
        'email' => $email,
        'role' => 'owner',
        'type' => $type,
        'iat' => $now,
        'nbf' => $now,
        'exp' => $now + $lifetime,
        'jti' => bin2hex(random_bytes(16)),
    ], ownerSecret(), 'HS256');
}

function verifyOwnerToken(string $token, string $type): object
{
    try {
        $claims = JWT::decode($token, new Key(ownerSecret(), 'HS256'));
    } catch (Throwable $e) {
        ownerResponse(false, 'Invalid or expired owner token', [], 401);
    }
    if (($claims->iss ?? null) !== 'sporto-api'
        || ($claims->role ?? null) !== 'owner'
        || ($claims->type ?? null) !== $type
        || (int) ($claims->user_id ?? $claims->sub ?? 0) < 1) {
        ownerResponse(false, 'Invalid owner token', [], 401);
    }
    return $claims;
}

function issueOwnerTokens(mysqli $db, int $id, string $name, string $email): array
{
    $access = createOwnerToken($id, $name, $email, 'access', OWNER_ACCESS_LIFETIME);
    $refresh = createOwnerToken($id, $name, $email, 'refresh', OWNER_REFRESH_LIFETIME);
    $hash = hash('sha256', $refresh);
    $stmt = $db->prepare('UPDATE ownerreg_tb SET token = ?, refresh_token = ? WHERE id = ?');
    $stmt->bind_param('ssi', $access, $hash, $id);
    $stmt->execute();
    $stmt->close();
    return [
        'access_token' => $access,
        'refresh_token' => $refresh,
        'token_type' => 'Bearer',
        'expires_in' => OWNER_ACCESS_LIFETIME,
        'refresh_expires_in' => OWNER_REFRESH_LIFETIME,
    ];
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST, OPTIONS');
    ownerResponse(false, 'Only POST method is allowed', [], 405);
}

$raw = file_get_contents('php://input');
$data = $raw === false ? null : json_decode($raw, true);
if (!is_array($data)) {
    ownerResponse(false, 'Valid JSON request body is required', [], 400);
}
$action = strtolower(trim((string) ($data['action'] ?? $_GET['action'] ?? '')));
if (!in_array($action, ['register', 'login', 'refresh', 'logout'], true)) {
    ownerResponse(false, 'Invalid action', [], 400);
}

$db = null;
try {
    $db = ownerDb();
    switch ($action) {
        case 'register':
            $name = trim((string) ($data['name'] ?? ''));
            $email = strtolower(trim((string) ($data['email'] ?? '')));
            $password = (string) ($data['password'] ?? '');
            if (mb_strlen($name) < 2 || mb_strlen($name) > 100
                || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254
                || strlen($password) < 8 || strlen($password) > 72) {
                ownerResponse(false, 'Invalid registration details', [], 422);
            }
            $stmt = $db->prepare('SELECT id FROM ownerreg_tb WHERE name = ? OR email = ? LIMIT 1');
            $stmt->bind_param('ss', $name, $email);
            $stmt->execute();
            $existing = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            if ($existing) {
                ownerResponse(false, 'Name or email is already registered', [], 409);
            }
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $empty = '';
            $stmt = $db->prepare('INSERT INTO ownerreg_tb (name, email, password, token, refresh_token, profile_image_url) VALUES (?, ?, ?, ?, ?, ?)');
            $stmt->bind_param('ssssss', $name, $email, $hash, $empty, $empty, $empty);
            $stmt->execute();
            $id = (int) $db->insert_id;
            $stmt->close();
            ownerResponse(true, 'Owner registered successfully. Please login.', [
                'user_id' => $id, 'name' => $name, 'email' => $email, 'role' => 'owner',
            ], 201);

        case 'login':
            $login = trim((string) ($data['username'] ?? $data['name'] ?? $data['email'] ?? ''));
            $password = (string) ($data['password'] ?? '');
            if ($login === '' || $password === '') {
                ownerResponse(false, 'Name/email and password are required', [], 400);
            }
            $stmt = $db->prepare('SELECT id, name, email, password, profile_image_url FROM ownerreg_tb WHERE name = ? OR email = ? LIMIT 1');
            $stmt->bind_param('ss', $login, $login);
            $stmt->execute();
            $owner = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            if (!$owner || !password_verify($password, (string) $owner['password'])) {
                ownerResponse(false, 'Invalid name/email or password', [], 401);
            }
            $id = (int) $owner['id'];
            $db->begin_transaction();
            $tokens = issueOwnerTokens($db, $id, (string) $owner['name'], (string) $owner['email']);
            $db->commit();
            ownerResponse(true, 'Owner login successful', [
                'user_id' => $id,
                'name' => $owner['name'],
                'email' => $owner['email'],
                'role' => 'owner',
                'profile_image_url' => $owner['profile_image_url'] ?? null,
                ...$tokens,
            ]);

        case 'refresh':
            $refresh = trim((string) ($data['refresh_token'] ?? ''));
            if ($refresh === '') {
                ownerResponse(false, 'Refresh token required', [], 422);
            }
            $claims = verifyOwnerToken($refresh, 'refresh');
            $id = (int) ($claims->user_id ?? $claims->sub);
            $hash = hash('sha256', $refresh);
            $db->begin_transaction();
            $stmt = $db->prepare('SELECT id, name, email, refresh_token FROM ownerreg_tb WHERE id = ? FOR UPDATE');
            $stmt->bind_param('i', $id);
            $stmt->execute();
            $owner = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            if (!$owner || !hash_equals((string) $owner['refresh_token'], $hash)) {
                $db->rollback();
                ownerResponse(false, 'Refresh token revoked or expired', [], 401);
            }
            $tokens = issueOwnerTokens($db, $id, (string) $owner['name'], (string) $owner['email']);
            $db->commit();
            ownerResponse(true, 'Owner token refreshed', [
                'user_id' => $id, 'role' => 'owner', ...$tokens,
            ]);

        case 'logout':
            $refresh = trim((string) ($data['refresh_token'] ?? ''));
            if ($refresh === '') {
                ownerResponse(false, 'Refresh token required', [], 422);
            }
            $claims = verifyOwnerToken($refresh, 'refresh');
            $id = (int) ($claims->user_id ?? $claims->sub);
            $hash = hash('sha256', $refresh);
            $db->begin_transaction();
            $stmt = $db->prepare('SELECT refresh_token FROM ownerreg_tb WHERE id = ? FOR UPDATE');
            $stmt->bind_param('i', $id);
            $stmt->execute();
            $owner = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            if (!$owner || !hash_equals((string) $owner['refresh_token'], $hash)) {
                $db->rollback();
                ownerResponse(false, 'Invalid or revoked refresh token', [], 401);
            }
            $empty = '';
            $stmt = $db->prepare('UPDATE ownerreg_tb SET token = ?, refresh_token = ? WHERE id = ?');
            $stmt->bind_param('ssi', $empty, $empty, $id);
            $stmt->execute();
            $stmt->close();
            $db->commit();
            ownerResponse(true, 'Owner logged out successfully');
    }
} catch (mysqli_sql_exception $e) {
    if ($db instanceof mysqli) {
        try { $db->rollback(); } catch (Throwable $ignored) {}
    }
    error_log('Sporto Owner DB Error: ' . $e->getMessage());
    if ((int) $e->getCode() === 1062 && $action === 'register') {
        ownerResponse(false, 'Name or email is already registered', [], 409);
    }
    ownerResponse(false, 'Owner database request failed', [], 500);
} catch (Throwable $e) {
    if ($db instanceof mysqli) {
        try { $db->rollback(); } catch (Throwable $ignored) {}
    }
    error_log('Sporto Owner Auth Error: ' . $e->getMessage());
    ownerResponse(false, 'Owner authentication request failed', [], 500);
}
