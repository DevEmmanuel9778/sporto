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
        b.id,
        b.user_id,
        b.turf_id,
        b.slot_id,
        b.booking_date,
        b.amount,
        b.status,
        t.name AS turf_name,
        t.location,
        s.start_time,
        s.end_time
     FROM bookings b
     INNER JOIN turfs t
        ON b.turf_id = t.id
     INNER JOIN turf_slots s
        ON b.slot_id = s.id
     WHERE b.user_id = ?
     ORDER BY b.id DESC"
);

$stmt->bind_param(
    "i",
    $userId
);

$stmt->execute();

$result = $stmt->get_result();

$bookings = [];

while ($row = $result->fetch_assoc()) {

    $bookings[] = [
        "id" => (int)$row['id'],
        "user_id" => (int)$row['user_id'],
        "turf_id" => (int)$row['turf_id'],
        "slot_id" => (int)$row['slot_id'],
        "turf_name" => $row['turf_name'],
        "location" => $row['location'],
        "booking_date" => $row['booking_date'],
        "start_time" => $row['start_time'],
        "end_time" => $row['end_time'],
        "amount" => (float)$row['amount'],
        "status" => $row['status']
    ];
}

echo json_encode([
    "status" => true,
    "message" => "Bookings fetched successfully",
    "bookings" => $bookings
]);

$stmt->close();
$con->close();

?>