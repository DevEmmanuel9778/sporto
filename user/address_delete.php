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

$data = json_decode(
    file_get_contents("php://input"),
    true
);

$addressId = (int)($data['address_id'] ?? 0);

if ($addressId <= 0) {
    echo json_encode([
        "status" => false,
        "message" => "Valid address ID is required"
    ]);
    exit;
}

/*
 * Delete only if the address belongs
 * to the logged-in user.
 */
$stmt = $con->prepare(
    "DELETE FROM address_tb
     WHERE id = ?
     AND user_id = ?"
);

$stmt->bind_param(
    "ii",
    $addressId,
    $userId
);

$stmt->execute();

if ($stmt->affected_rows === 0) {

    echo json_encode([
        "status" => false,
        "message" => "Address not found"
    ]);

    exit;
}

echo json_encode([
    "status" => true,
    "message" => "Address deleted successfully"
]);

$stmt->close();
$con->close();

?>