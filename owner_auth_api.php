<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

function sendResponse(bool $status, string $message, array $data = [], int $httpCode = 200): never
{
    http_response_code($httpCode);
    echo json_encode(array_merge(['status' => $status, 'message' => $message], $data), JSON_UNESCAPED_UNICODE);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST, OPTIONS');
    sendResponse(false, 'Only POST method is allowed', [], 405);
}

$input = file_get_contents('php://input');
$data = json_decode($input ?: '', true);
if (!is_array($data)) {
    sendResponse(false, 'Valid JSON request body is required', [], 400);
}

$action = strtolower(trim((string)($data['action'] ?? '')));
if (!in_array($action, ['login', 'register'], true)) {
    sendResponse(false, 'Invalid action. Use login or register', [], 400);
}

$host = getenv('DB_HOST');
$port = (int)getenv('DB_PORT');
$dbname = getenv('DB_NAME');
$username = getenv('DB_USER');
$password = getenv('DB_PASSWORD');
$secretKey = getenv('JWT_SECRET');

if ($host === false || trim($host) === '' || $port <= 0 ||
    $dbname === false || trim($dbname) === '' ||
    $username === false || trim($username) === '' || $password === false) {
    sendResponse(false, 'Database environment variables are missing or invalid', [], 500);
}
if ($secretKey === false || trim($secretKey) === '') {
    sendResponse(false, 'JWT_SECRET environment variable is missing', [], 500);
}

try {
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $con = mysqli_init();
    if ($con === false) {
        throw new RuntimeException('Could not initialize database connection');
    }
    mysqli_ssl_set($con, null, null, null, null, null);
    mysqli_real_connect($con, $host, $username, $password, $dbname, $port, null, MYSQLI_CLIENT_SSL);
    $con->set_charset('utf8mb4');
} catch (Throwable $e) {
    error_log('Owner auth database connection failed: ' . $e->getMessage());
    sendResponse(false, 'Database connection failed', [], 500);
}

if ($action === 'register') {
    $name = trim((string)($data['name'] ?? ''));
    $email = strtolower(trim((string)($data['email'] ?? '')));
    $plainPassword = (string)($data['password'] ?? '');

    if (mb_strlen($name) < 2 || mb_strlen($name) > 100) {
        sendResponse(false, 'Name must contain 2 to 100 characters', [], 422);
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
        sendResponse(false, 'A valid email is required', [], 422);
    }
    if (strlen($plainPassword) < 8 || strlen($plainPassword) > 72) {
        sendResponse(false, 'Password must contain 8 to 72 characters', [], 422);
    }

    try {
        // Login supports either name or email; keep both identifiers unique.
        $check = $con->prepare('SELECT id, name, email FROM ownerreg_tb WHERE name = ? OR email = ? LIMIT 1');
        $check->bind_param('ss', $name, $email);
        $check->execute();
        $existing = $check->get_result()->fetch_assoc();
        $check->close();

        if ($existing !== null) {
            sendResponse(false, 'Name or email is already registered', [], 409);
        }

        $passwordHash = password_hash($plainPassword, PASSWORD_DEFAULT);
        if ($passwordHash === false) {
            throw new RuntimeException('Password hashing failed');
        }

        // Assumes id is AUTO_INCREMENT and token, refresh_token,
        // profile_image_url are nullable or have defaults.
        $stmt = $con->prepare('INSERT INTO ownerreg_tb (name, email, password) VALUES (?, ?, ?)');
        $stmt->bind_param('sss', $name, $email, $passwordHash);
        $stmt->execute();
        $ownerId = $con->insert_id;
        $stmt->close();

        sendResponse(true, 'Owner registered successfully. Please login.', [
            'user_id' => (int)$ownerId,
            'name' => $name,
            'email' => $email,
            'role' => 'owner',
        ], 201);
    } catch (mysqli_sql_exception $e) {
        if ((int)$e->getCode() === 1062) {
            sendResponse(false, 'Name or email is already registered', [], 409);
        }
        error_log('Owner registration DB error: ' . $e->getMessage());
        sendResponse(false, 'Registration failed', [], 500);
    } catch (Throwable $e) {
        error_log('Owner registration error: ' . $e->getMessage());
        sendResponse(false, 'Registration failed', [], 500);
    }
}

// Existing owner login response and JWT claim names are preserved.
$ownerLogin = trim((string)($data['username'] ?? $data['name'] ?? $data['email'] ?? ''));
$loginPassword = (string)($data['password'] ?? '');
if ($ownerLogin === '' || $loginPassword === '') {
    sendResponse(false, 'Name/email and password are required', [], 400);
}

try {
    $stmt = $con->prepare(
        'SELECT id, name, email, password, profile_image_url
         FROM ownerreg_tb WHERE name = ? OR email = ? LIMIT 1'
    );
    $stmt->bind_param('ss', $ownerLogin, $ownerLogin);
    $stmt->execute();
    $owner = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if ($owner === null || !password_verify($loginPassword, (string)$owner['password'])) {
        sendResponse(false, 'Invalid name/email or password', [], 401);
    }

    $ownerId = (int)$owner['id'];
    $name = (string)$owner['name'];
    $email = (string)$owner['email'];
    $issuedAt = time();
    $accessToken = JWT::encode([
        'iss' => 'sporto-api',
        'iat' => $issuedAt,
        'exp' => $issuedAt + 900,
        'user_id' => $ownerId,
        'name' => $name,
        'email' => $email,
        'role' => 'owner',
        'type' => 'access',
    ], $secretKey, 'HS256');

    $updateStmt = $con->prepare('UPDATE ownerreg_tb SET token = ? WHERE id = ?');
    $updateStmt->bind_param('si', $accessToken, $ownerId);
    $updateStmt->execute();
    $updateStmt->close();

    sendResponse(true, 'Owner login successful', [
        'user_id' => $ownerId,
        'name' => $name,
        'email' => $email,
        'role' => 'owner',
        'profile_image_url' => $owner['profile_image_url'] ?? null,
        'access_token' => $accessToken,
    ]);
} catch (Throwable $e) {
    error_log('Owner login error: ' . $e->getMessage());
    sendResponse(false, 'Login failed', [], 500);
}
