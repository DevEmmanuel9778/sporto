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
        "message" => "Only turf owners can update turfs"
    ]);
    exit;
}

$data = json_decode(
    file_get_contents("php://input"),
    true
);

$turfId = (int)($data['turf_id'] ?? 0);

$name = trim($data['name'] ?? '');
$turfType = trim($data['turf_type'] ?? '');
$description = trim($data['description'] ?? '');
$location = trim($data['location'] ?? '');
$contact = trim($data['contact'] ?? '');
$price = $data['price'] ?? '';
$status = trim($data['status'] ?? 'active');

if ($turfId <= 0) {
    echo json_encode([
        "status" => false,
        "message" => "Valid turf ID is required"
    ]);
    exit;
}

if (
    $name === '' ||
    $turfType === '' ||
    $description === '' ||
    $location === '' ||
    $contact === '' ||
    $price === ''
) {
    echo json_encode([
        "status" => false,
        "message" => "All turf fields are required"
    ]);
    exit;
}

if (!is_numeric($price) || $price <= 0) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid turf price"
    ]);
    exit;
}

if (!preg_match('/^[0-9]{10}$/', $contact)) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid contact number"
    ]);
    exit;
}

$checkStmt = $con->prepare(
    "SELECT id
     FROM turfs
     WHERE id = ?
     AND owner_id = ?
     LIMIT 1"
);

$checkStmt->bind_param(
    "ii",
    $turfId,
    $ownerId
);

$checkStmt->execute();

$checkResult = $checkStmt->get_result();

if ($checkResult->num_rows === 0) {

    echo json_encode([
        "status" => false,
        "message" => "Turf not found or unauthorized"
    ]);

    exit;
}

$checkStmt->close();

$stmt = $con->prepare(
    "UPDATE turfs
     SET
        name = ?,
        turf_type = ?,
        description = ?,
        location = ?,
        contact = ?,
        price = ?,
        status = ?
     WHERE id = ?
     AND owner_id = ?"
);

$stmt->bind_param(
    "sssssdsii",
    $name,
    $turfType,
    $description,
    $location,
    $contact,
    $price,
    $status,
    $turfId,
    $ownerId
);

if ($stmt->execute()) {

    echo json_encode([
        "status" => true,
        "message" => "Turf updated successfully"
    ]);

} else {

    echo json_encode([
        "status" => false,
        "message" => "Failed to update turf"
    ]);
}

$stmt->close();
$con->close();

?>