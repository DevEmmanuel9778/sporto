<?php

header("Content-Type: application/json");

require_once "../connection.php";
require_once "../config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode([
        "status" => false,
        "message" => "Only POST method is allowed"
    ]);
    exit;
}

$data = json_decode(
    file_get_contents("php://input"),
    true
);

$name = trim($data['name'] ?? '');
$email = trim($data['email'] ?? '');
$phone = trim($data['phone'] ?? '');
$password = $data['password'] ?? '';

/*
|--------------------------------------------------------------------------
| Validate fields
|--------------------------------------------------------------------------
*/

if (
    $name === '' ||
    $email === '' ||
    $phone === '' ||
    $password === ''
) {
    echo json_encode([
        "status" => false,
        "message" => "All fields are required"
    ]);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid email address"
    ]);
    exit;
}

if (strlen($password) < 6) {
    echo json_encode([
        "status" => false,
        "message" => "Password must contain at least 6 characters"
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| Check existing email
|--------------------------------------------------------------------------
*/

$check = $con->prepare(
    "SELECT user_id
     FROM userreg_tb
     WHERE email = ?
     LIMIT 1"
);

if (!$check) {
    echo json_encode([
        "status" => false,
        "message" => "Database query error",
        "error_detail" => $con->error
    ]);
    exit;
}

$check->bind_param("s", $email);

if (!$check->execute()) {
    echo json_encode([
        "status" => false,
        "message" => "Failed to check email",
        "error_detail" => $check->error
    ]);
    $check->close();
    $con->close();
    exit;
}

$result = $check->get_result();

if ($result->num_rows > 0) {
    echo json_encode([
        "status" => false,
        "message" => "Email already registered"
    ]);

    $check->close();
    $con->close();
    exit;
}

$check->close();

/*
|--------------------------------------------------------------------------
| Hash password
|--------------------------------------------------------------------------
*/

$hashedPassword = password_hash(
    $password,
    PASSWORD_DEFAULT
);

/*
|--------------------------------------------------------------------------
| Insert user first
|--------------------------------------------------------------------------
*/

$stmt = $con->prepare(
    "INSERT INTO userreg_tb
    (
        name,
        email,
        phone,
        password,
        token,
        refresh_token
    )
    VALUES (?, ?, ?, ?, ?, ?)"
);

if (!$stmt) {
    echo json_encode([
        "status" => false,
        "message" => "Database insert query error",
        "error_detail" => $con->error
    ]);

    $con->close();
    exit;
}

/*
|--------------------------------------------------------------------------
| Temporary empty values because columns are NOT NULL
|--------------------------------------------------------------------------
*/

$token = '';
$refreshToken = '';

$stmt->bind_param(
    "ssssss",
    $name,
    $email,
    $phone,
    $hashedPassword,
    $token,
    $refreshToken
);

if (!$stmt->execute()) {
    echo json_encode([
        "status" => false,
        "message" => "Registration failed",
        "error_detail" => $stmt->error
    ]);

    $stmt->close();
    $con->close();
    exit;
}

$userId = $stmt->insert_id;

$stmt->close();

/*
|--------------------------------------------------------------------------
| JWT CONFIG
|--------------------------------------------------------------------------
*/

if (!defined('JWT_SECRET')) {
    echo json_encode([
        "status" => false,
        "message" => "JWT_SECRET is not configured"
    ]);

    $con->close();
    exit;
}

$issuedAt = time();

/*
|--------------------------------------------------------------------------
| ACCESS TOKEN
|--------------------------------------------------------------------------
*/

$accessPayload = [
    "iss" => "sporto",
    "iat" => $issuedAt,
    "exp" => $issuedAt + (60 * 60),
    "type" => "access",
    "user_id" => (int)$userId,
    "name" => $name,
    "email" => $email
];

$accessToken = JWT::encode(
    $accessPayload,
    JWT_SECRET,
    'HS256'
);

/*
|--------------------------------------------------------------------------
| REFRESH TOKEN
|--------------------------------------------------------------------------
*/

$refreshPayload = [
    "iss" => "sporto",
    "iat" => $issuedAt,
    "exp" => $issuedAt + (60 * 60 * 24 * 30),
    "type" => "refresh",
    "user_id" => (int)$userId,
    "email" => $email
];

$refreshToken = JWT::encode(
    $refreshPayload,
    JWT_SECRET,
    'HS256'
);

/*
|--------------------------------------------------------------------------
| Save tokens in database
|--------------------------------------------------------------------------
*/

$update = $con->prepare(
    "UPDATE userreg_tb
     SET token = ?, refresh_token = ?
     WHERE user_id = ?"
);

if (!$update) {
    echo json_encode([
        "status" => false,
        "message" => "Token update query error",
        "error_detail" => $con->error
    ]);

    $con->close();
    exit;
}

$update->bind_param(
    "ssi",
    $accessToken,
    $refreshToken,
    $userId
);

if (!$update->execute()) {
    echo json_encode([
        "status" => false,
        "message" => "Failed to save authentication tokens",
        "error_detail" => $update->error
    ]);

    $update->close();
    $con->close();
    exit;
}

$update->close();

/*
|--------------------------------------------------------------------------
| Registration successful
|--------------------------------------------------------------------------
*/

echo json_encode([
    "status" => true,
    "message" => "success",
    "user_id" => (int)$userId,
    "name" => $name,
    "email" => $email,
    "phone" => $phone,
    "access_token" => $accessToken,
    "refresh_token" => $refreshToken
]);

$con->close();

?>