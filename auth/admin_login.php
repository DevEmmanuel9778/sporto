<?php

header("Content-Type: application/json");

require_once "../connection.php";
require_once "../config/jwt.php";

use Firebase\JWT\JWT;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode([
        "status" => false,
        "message" => "Only POST method is allowed"
    ]);
    exit;
}

$data = json_decode(file_get_contents("php://input"), true);

$username = trim($data['username'] ?? '');
$password = $data['password'] ?? '';

if ($username === '' || $password === '') {
    echo json_encode([
        "status" => false,
        "message" => "Username and password are required"
    ]);
    exit;
}

$stmt = $con->prepare(
    "SELECT id, username, password
     FROM adminreg_tb
     WHERE username = ?
     LIMIT 1"
);

$stmt->bind_param("s", $username);
$stmt->execute();

$result = $stmt->get_result();

if ($result->num_rows === 0) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid username or password"
    ]);
    exit;
}

$admin = $result->fetch_assoc();

if (!password_verify($password, $admin['password'])) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid username or password"
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| Access Token
|--------------------------------------------------------------------------
*/

$accessPayload = [
    "iss" => $issuer,
    "iat" => time(),
    "exp" => time() + $access_token_expiry,
    "user_id" => $admin['id'],
    "role" => "admin"
];

$accessToken = JWT::encode(
    $accessPayload,
    $secret_key,
    "HS256"
);

/*
|--------------------------------------------------------------------------
| Refresh Token
|--------------------------------------------------------------------------
*/

$refreshPayload = [
    "iss" => $issuer,
    "iat" => time(),
    "exp" => time() + $refresh_token_expiry,
    "user_id" => $admin['id'],
    "role" => "admin",
    "type" => "refresh"
];

$refreshToken = JWT::encode(
    $refreshPayload,
    $secret_key,
    "HS256"
);

/*
|--------------------------------------------------------------------------
| Store Refresh Token Hash
|--------------------------------------------------------------------------
*/

$tokenHash = hash('sha256', $refreshToken);

$expiresAt = date(
    'Y-m-d H:i:s',
    time() + $refresh_token_expiry
);

$tokenStmt = $con->prepare(
    "INSERT INTO refresh_tokens
    (user_type, user_id, token_hash, expires_at, revoked)
    VALUES (?, ?, ?, ?, 0)"
);

$userType = "admin";

$tokenStmt->bind_param(
    "siss",
    $userType,
    $admin['id'],
    $tokenHash,
    $expiresAt
);

$tokenStmt->execute();

/*
|--------------------------------------------------------------------------
| Response
|--------------------------------------------------------------------------
*/

echo json_encode([
    "status" => true,
    "message" => "Admin login successful",

    "admin" => [
        "id" => $admin['id'],
        "username" => $admin['username'],
        "role" => "admin"
    ],

    "access_token" => $accessToken,
    "refresh_token" => $refreshToken
]);

$stmt->close();
$tokenStmt->close();
$con->close();

?>