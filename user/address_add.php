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

$name = trim($data['name'] ?? '');
$phone = trim($data['phone'] ?? '');
$address = trim($data['address'] ?? '');
$city = trim($data['city'] ?? '');
$district = trim($data['district'] ?? '');
$state = trim($data['state'] ?? '');
$pincode = trim($data['pincode'] ?? '');
$isDefault = isset($data['is_default'])
    ? (int)$data['is_default']
    : 0;

if (
    $name === '' ||
    $phone === '' ||
    $address === '' ||
    $city === '' ||
    $district === '' ||
    $state === '' ||
    $pincode === ''
) {
    echo json_encode([
        "status" => false,
        "message" => "All address fields are required"
    ]);
    exit;
}

if (!preg_match('/^[0-9]{6}$/', $pincode)) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid pincode"
    ]);
    exit;
}

if ($isDefault === 1) {

    $resetStmt = $con->prepare(
        "UPDATE address_tb
         SET is_default = 0
         WHERE user_id = ?"
    );

    $resetStmt->bind_param("i", $userId);
    $resetStmt->execute();
    $resetStmt->close();
}

$stmt = $con->prepare(
    "INSERT INTO address_tb
    (
        user_id,
        name,
        phone,
        address,
        city,
        district,
        state,
        pincode,
        is_default
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
);

$stmt->bind_param(
    "isssssssi",
    $userId,
    $name,
    $phone,
    $address,
    $city,
    $district,
    $state,
    $pincode,
    $isDefault
);

if ($stmt->execute()) {

    echo json_encode([
        "status" => true,
        "message" => "Address added successfully",
        "address_id" => $stmt->insert_id
    ]);

} else {

    echo json_encode([
        "status" => false,
        "message" => "Failed to add address"
    ]);
}

$stmt->close();
$con->close();

?>