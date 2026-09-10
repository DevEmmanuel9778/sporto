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
        "message" => "Only turf owners can add turfs"
    ]);
    exit;
}

$data = json_decode(
    file_get_contents("php://input"),
    true
);

$name = trim($data['name'] ?? '');
$turfType = trim($data['turf_type'] ?? '');
$description = trim($data['description'] ?? '');
$location = trim($data['location'] ?? '');
$contact = trim($data['contact'] ?? '');
$price = $data['price'] ?? '';

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

$status = "active";

$stmt = $con->prepare(
    "INSERT INTO turfs
    (
        owner_id,
        name,
        turf_type,
        description,
        location,
        contact,
        price,
        status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
);

$stmt->bind_param(
    "isssssds",
    $ownerId,
    $name,
    $turfType,
    $description,
    $location,
    $contact,
    $price,
    $status
);

if ($stmt->execute()) {

    echo json_encode([
        "status" => true,
        "message" => "Turf added successfully",
        "turf_id" => $stmt->insert_id
    ]);

} else {

    echo json_encode([
        "status" => false,
        "message" => "Failed to add turf"
    ]);
}

$stmt->close();
$con->close();

?>