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
    "SELECT
        id,
        name,
        phone,
        address,
        city,
        district,
        state,
        pincode,
        is_default
     FROM address_tb
     WHERE user_id = ?
     ORDER BY is_default DESC, id DESC"
);

$stmt->bind_param("i", $userId);
$stmt->execute();

$result = $stmt->get_result();

$addresses = [];

while ($row = $result->fetch_assoc()) {

    $addresses[] = [
        "id" => $row['id'],
        "name" => $row['name'],
        "phone" => $row['phone'],
        "address" => $row['address'],
        "city" => $row['city'],
        "district" => $row['district'],
        "state" => $row['state'],
        "pincode" => $row['pincode'],
        "is_default" => (int)$row['is_default']
    ];
}

echo json_encode([
    "status" => true,
    "message" => "Addresses fetched successfully",
    "addresses" => $addresses
]);

$stmt->close();
$con->close();

?>