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
| Find Owner
|--------------------------------------------------------------------------
*/

$stmt = $con->prepare(
    "SELECT id, name, email, phone, password
     FROM turf_owners
     WHERE email = ?
     LIMIT 1"
);

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

$owner = $result->fetch_assoc();

/*
|--------------------------------------------------------------------------
| Verify Password
|--------------------------------------------------------------------------
*/

if (!password_verify($password, $owner['password'])) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid email or password"
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
    "user_id" => $owner['id'],
    "role" => "owner"
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
    "user_id" => $owner['id'],
    "role" => "owner",
    "type" => "refresh"
];

$refreshToken = JWT::encode(
    $refreshPayload,
    $secret_key,
    "HS256"
);

/*
|--------------------------------------------------------------------------
| Response
|--------------------------------------------------------------------------
*/

echo json_encode([
    "status" => true,
    "message" => "Owner login successful",

    "owner" => [
        "id" => $owner['id'],
        "name" => $owner['name'],
        "email" => $owner['email'],
        "phone" => $owner['phone'],
        "role" => "owner"
    ],

    "access_token" => $accessToken,
    "refresh_token" => $refreshToken
]);

$stmt->close();
$con->close();

?>