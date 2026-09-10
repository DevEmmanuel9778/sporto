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

$data = json_decode(file_get_contents("php://input"), true);

$refreshToken = $data['refresh_token'] ?? '';

if ($refreshToken === '') {
    echo json_encode([
        "status" => false,
        "message" => "Refresh token is required"
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| Decode Refresh Token
|--------------------------------------------------------------------------
*/

try {

    $decoded = JWT::decode(
        $refreshToken,
        new Key($secret_key, "HS256")
    );

} catch (Exception $e) {

    echo json_encode([
        "status" => false,
        "message" => "Invalid or expired refresh token"
    ]);

    exit;
}

/*
|--------------------------------------------------------------------------
| Check Token Type
|--------------------------------------------------------------------------
*/

if (
    !isset($decoded->type) ||
    $decoded->type !== "refresh"
) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid token type"
    ]);
    exit;
}

$userId = $decoded->user_id ?? null;
$role = $decoded->role ?? null;

if (!$userId || !$role) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid token data"
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| Check Database
|--------------------------------------------------------------------------
*/

$tokenHash = hash('sha256', $refreshToken);

$stmt = $con->prepare(
    "SELECT id
     FROM refresh_tokens
     WHERE user_type = ?
     AND user_id = ?
     AND token_hash = ?
     AND revoked = 0
     AND expires_at > NOW()
     LIMIT 1"
);

$stmt->bind_param(
    "sis",
    $role,
    $userId,
    $tokenHash
);

$stmt->execute();

$result = $stmt->get_result();

if ($result->num_rows === 0) {

    echo json_encode([
        "status" => false,
        "message" => "Refresh token is not valid"
    ]);

    exit;
}

/*
|--------------------------------------------------------------------------
| Create New Access Token
|--------------------------------------------------------------------------
*/

$accessPayload = [
    "iss" => $issuer,
    "iat" => time(),
    "exp" => time() + $access_token_expiry,
    "user_id" => $userId,
    "role" => $role
];

$newAccessToken = JWT::encode(
    $accessPayload,
    $secret_key,
    "HS256"
);

echo json_encode([
    "status" => true,
    "message" => "Access token refreshed successfully",
    "access_token" => $newAccessToken
]);

$stmt->close();
$con->close();

?>