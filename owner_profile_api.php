<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, PUT, PATCH, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function reply(bool $status, string $message, array $extra = [], int $code = 200): never {
    http_response_code($code);
    echo json_encode(array_merge(['status' => $status, 'message' => $message], $extra), JSON_UNESCAPED_UNICODE);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'] ?? '';
if (!in_array($method, ['GET', 'PUT', 'PATCH'], true)) {
    header('Allow: GET, PUT, PATCH, OPTIONS');
    reply(false, 'Method not allowed', [], 405);
}

$jwtSecret = getenv('JWT_SECRET');
if (!is_string($jwtSecret) || $jwtSecret === '') {
    reply(false, 'Server configuration error', [], 500);
}

$authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
if ($authorization === '' && function_exists('getallheaders')) {
    foreach (getallheaders() as $key => $value) {
        if (strcasecmp($key, 'Authorization') === 0) {
            $authorization = (string)$value;
            break;
        }
    }
}
if (!preg_match('/^Bearer\s+(\S+)$/i', trim($authorization), $matches)) {
    reply(false, 'Bearer access token required', [], 401);
}

try {
    $claims = (array)JWT::decode($matches[1], new Key($jwtSecret, 'HS256'));
    if (($claims['type'] ?? '') !== 'access' || ($claims['role'] ?? '') !== 'owner') {
        reply(false, 'Owner access token required', [], 403);
    }
    $ownerId = filter_var($claims['user_id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    if ($ownerId === false) {
        reply(false, 'Invalid token owner ID', [], 401);
    }
} catch (Throwable $e) {
    reply(false, 'Invalid or expired access token', [], 401);
}

$host = getenv('DB_HOST');
$port = (int)(getenv('DB_PORT') ?: 3306);
$dbname = getenv('DB_NAME');
$dbUser = getenv('DB_USER');
$dbPassword = getenv('DB_PASSWORD');
if (!$host || !$dbname || !$dbUser || $dbPassword === false || $port < 1) {
    reply(false, 'Database configuration missing', [], 500);
}

try {
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $db = mysqli_init();
    if ($db === false) {
        throw new RuntimeException('Cannot initialize database');
    }
    // Match the existing owner login: Aiven MySQL over TLS.
    mysqli_ssl_set($db, null, null, null, null, null);
    mysqli_real_connect($db, $host, $dbUser, $dbPassword, $dbname, $port, null, MYSQLI_CLIENT_SSL);
    $db->set_charset('utf8mb4');
} catch (Throwable $e) {
    reply(false, 'Database connection failed', [], 500);
}

function ownerProfile(mysqli $db, int $ownerId): array {
    $stmt = $db->prepare('SELECT id, name, email, profile_image_url FROM ownerreg_tb WHERE id = ? LIMIT 1');
    $stmt->bind_param('i', $ownerId);
    $stmt->execute();
    $owner = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if (!$owner) {
        reply(false, 'Owner not found', [], 404);
    }
    return [
        'id' => (int)$owner['id'],
        'name' => (string)$owner['name'],
        'email' => (string)$owner['email'],
        'profile_image_url' => $owner['profile_image_url'],
    ];
}

try {
    if ($method === 'GET') {
        reply(true, 'Owner profile fetched', ['owner' => ownerProfile($db, (int)$ownerId)]);
    }

    $raw = file_get_contents('php://input');
    $data = json_decode($raw ?: '', true);
    if (!is_array($data) || array_is_list($data)) {
        reply(false, 'A JSON object is required', [], 400);
    }

    $updates = [];
    $types = '';
    $values = [];

    if (array_key_exists('name', $data)) {
        if (!is_string($data['name'])) reply(false, 'Invalid name', [], 422);
        $name = trim($data['name']);
        if ($name === '' || mb_strlen($name) > 100) reply(false, 'Name must be 1–100 characters', [], 422);
        $updates[] = 'name = ?';
        $types .= 's';
        $values[] = $name;
    }
    if (array_key_exists('email', $data)) {
        if (!is_string($data['email'])) reply(false, 'Invalid email', [], 422);
        $email = strtolower(trim($data['email']));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
            reply(false, 'Valid email required', [], 422);
        }
        $check = $db->prepare('SELECT id FROM ownerreg_tb WHERE email = ? AND id <> ? LIMIT 1');
        $check->bind_param('si', $email, $ownerId);
        $check->execute();
        $duplicate = $check->get_result()->fetch_assoc();
        $check->close();
        if ($duplicate) reply(false, 'Email is already registered', [], 409);
        $updates[] = 'email = ?';
        $types .= 's';
        $values[] = $email;
    }
    if (array_key_exists('profile_image_url', $data)) {
        $image = $data['profile_image_url'];
        if ($image !== null) {
            if (!is_string($image) || strlen($image) > 2048 ||
                !filter_var($image, FILTER_VALIDATE_URL) ||
                !in_array(strtolower((string)parse_url($image, PHP_URL_SCHEME)), ['https'], true)) {
                reply(false, 'Profile image must be an HTTPS URL or null', [], 422);
            }
        }
        $updates[] = 'profile_image_url = ?';
        $types .= 's';
        $values[] = $image;
    }
    if (!$updates) reply(false, 'Supply name, email or profile_image_url', [], 422);

    $sql = 'UPDATE ownerreg_tb SET ' . implode(', ', $updates) . ' WHERE id = ?';
    $types .= 'i';
    $values[] = (int)$ownerId;
    $stmt = $db->prepare($sql);
    $stmt->bind_param($types, ...$values);
    $stmt->execute();
    $stmt->close();
    reply(true, 'Owner profile updated', ['owner' => ownerProfile($db, (int)$ownerId)]);
} catch (mysqli_sql_exception $e) {
    if ((int)$e->getCode() === 1062) reply(false, 'Name or email is already registered', [], 409);
    reply(false, 'Database operation failed', [], 500);
} catch (Throwable $e) {
    reply(false, 'Could not process profile request', [], 500);
}
