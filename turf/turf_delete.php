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

$ownerId = $decoded->user_id ?? null;
$role = $decoded->role ?? null;

if (!$ownerId || $role !== "owner") {
    echo json_encode([
        "status" => false,
        "message" => "Only turf owners can delete turfs"
    ]);
    exit;
}

$data = json_decode(
    file_get_contents("php://input"),
    true
);

$turfId = (int)($data['turf_id'] ?? 0);

if ($turfId <= 0) {
    echo json_encode([
        "status" => false,
        "message" => "Valid turf ID is required"
    ]);
    exit;
}

$stmt = $con->prepare(
    "UPDATE turfs
     SET status = 'inactive'
     WHERE id = ?
     AND owner_id = ?"
);

$stmt->bind_param(
    "ii",
    $turfId,
    $ownerId
);

$stmt->execute();

if ($stmt->affected_rows === 0) {

    echo json_encode([
        "status" => false,
        "message" => "Turf not found or already inactive"
    ]);

    exit;
}

echo json_encode([
    "status" => true,
    "message" => "Turf deleted successfully"
]);

$stmt->close();
$con->close();

?>