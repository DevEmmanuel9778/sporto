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

$email = trim($data['email'] ?? '');
$password = $data['password'] ?? '';

if ($email === '' || $password === '') {
    echo json_encode([
        "status" => false,
        "message" => "Email and password are required"
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| Find User
|--------------------------------------------------------------------------
*/

$stmt = $con->prepare(
    "SELECT user_id, name, email, phone, password
     FROM userreg_tb
     WHERE email = ?
     LIMIT 1"
);

if (!$stmt) {
    echo json_encode([
        "status" => false,
        "message" => "Database query failed",
        "error_detail" => $con->error
    ]);
    exit;
}

$stmt->bind_param("s", $email);
$stmt->execute();

$result = $stmt->get_result();

if ($result->num_rows === 0) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid email or password"
    ]);
    exit;
}

$user = $result->fetch_assoc();

/*
|--------------------------------------------------------------------------
| Verify Password
|--------------------------------------------------------------------------
*/

if (!password_verify($password, $user['password'])) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid email or password"
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| Time
|--------------------------------------------------------------------------
*/

$issuedAt = time();

/*
|--------------------------------------------------------------------------
| Access Token
|--------------------------------------------------------------------------
*/

$accessPayload = [
    "iss" => $issuer,
    "iat" => $issuedAt,
    "exp" => $issuedAt + $access_token_expiry,
    "user_id" => (int)$user['user_id'],
    "name" => $user['name'],
    "email" => $user['email'],
    "role" => "user",
    "type" => "access"
];

$accessToken = JWT::encode(
    $accessPayload,
    $secret_key,
    'HS256'
);

/*
|--------------------------------------------------------------------------
| Refresh Token
|--------------------------------------------------------------------------
*/

$refreshPayload = [
    "iss" => $issuer,
    "iat" => $issuedAt,
    "exp" => $issuedAt + $refresh_token_expiry,
    "user_id" => (int)$user['user_id'],
    "email" => $user['email'],
    "role" => "user",
    "type" => "refresh"
];

$refreshToken = JWT::encode(
    $refreshPayload,
    $secret_key,
    'HS256'
);

/*
|--------------------------------------------------------------------------
| Save Tokens
|--------------------------------------------------------------------------
*/

$updateStmt = $con->prepare(
    "UPDATE userreg_tb
     SET token = ?, refresh_token = ?
     WHERE user_id = ?"
);

if (!$updateStmt) {
    echo json_encode([
        "status" => false,
        "message" => "Failed to prepare token update",
        "error_detail" => $con->error
    ]);
    exit;
}

$userId = (int)$user['user_id'];

$updateStmt->bind_param(
    "ssi",
    $accessToken,
    $refreshToken,
    $userId
);

if (!$updateStmt->execute()) {
    echo json_encode([
        "status" => false,
        "message" => "Failed to save authentication tokens",
        "error_detail" => $updateStmt->error
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| Success Response
|--------------------------------------------------------------------------
*/

echo json_encode([
    "status" => true,
    "message" => "success",

    "user_id" => $userId,
    "name" => $user['name'],
    "email" => $user['email'],
    "phone" => $user['phone'],
    "role" => "user",

    "access_token" => $accessToken,
    "refresh_token" => $refreshToken
]);

$updateStmt->close();
$stmt->close();
$con->close();

?>