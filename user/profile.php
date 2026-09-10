<?php

header("Content-Type: application/json");

require_once "../connection.php";
require_once "../config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    echo json_encode([
        "status" => false,
        "message" => "Only GET method is allowed"
    ]);
    exit;
}

$headers = getallheaders();

$authHeader = $headers['Authorization'] ?? '';

if ($authHeader === '') {
    echo json_encode([
        "status" => false,
        "message" => "Authorization token is required"
    ]);
    exit;
}

if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid authorization format"
    ]);
    exit;
}

$accessToken = $matches[1];

try {

    $decoded = JWT::decode(
        $accessToken,
        new Key($secret_key, "HS256")
    );

} catch (Throwable $e) {

    echo json_encode([
        "status" => false,
        "message" => "Invalid or expired access token"
    ]);
    exit;
}

$userId = $decoded->user_id ?? null;
$role = $decoded->role ?? null;

if (!$userId || $role !== "user") {
    echo json_encode([
        "status" => false,
        "message" => "Unauthorized access"
    ]);
    exit;
}

$stmt = $con->prepare(
    "SELECT id, name, email, phone
     FROM users
     WHERE id = ?
     LIMIT 1"
);

$stmt->bind_param("i", $userId);
$stmt->execute();

$result = $stmt->get_result();

if ($result->num_rows === 0) {

    echo json_encode([
        "status" => false,
        "message" => "User not found"
    ]);

    exit;
}

$user = $result->fetch_assoc();

echo json_encode([
    "status" => true,
    "message" => "Profile fetched successfully",
    "user" => [
        "id" => $user['id'],
        "name" => $user['name'],
        "email" => $user['email'],
        "phone" => $user['phone'],
        "role" => "user"
    ]
]);

$stmt->close();
$con->close();

?>