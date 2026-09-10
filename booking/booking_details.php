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

$bookingId = (int)($_GET['id'] ?? 0);

if ($bookingId <= 0) {
    echo json_encode([
        "status" => false,
        "message" => "Valid booking ID is required"
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
        t.turf_type,
        t.description,
        t.location,
        t.contact,

        s.start_time,
        s.end_time,
        s.price AS slot_price,

        o.name AS owner_name,
        o.phone AS owner_phone

     FROM bookings b

     INNER JOIN turfs t
        ON b.turf_id = t.id

     INNER JOIN turf_slots s
        ON b.slot_id = s.id

     INNER JOIN turf_owners o
        ON t.owner_id = o.id

     WHERE b.id = ?
     AND b.user_id = ?

     LIMIT 1"
);

$stmt->bind_param(
    "ii",
    $bookingId,
    $userId
);

$stmt->execute();

$result = $stmt->get_result();

if ($result->num_rows === 0) {

    echo json_encode([
        "status" => false,
        "message" => "Booking not found"
    ]);

    exit;
}

$booking = $result->fetch_assoc();

echo json_encode([
    "status" => true,
    "message" => "Booking details fetched successfully",

    "booking" => [
        "id" => (int)$booking['id'],
        "user_id" => (int)$booking['user_id'],
        "turf_id" => (int)$booking['turf_id'],
        "slot_id" => (int)$booking['slot_id'],

        "booking_date" => $booking['booking_date'],
        "start_time" => $booking['start_time'],
        "end_time" => $booking['end_time'],

        "amount" => (float)$booking['amount'],
        "status" => $booking['status'],

        "turf" => [
            "name" => $booking['turf_name'],
            "turf_type" => $booking['turf_type'],
            "description" => $booking['description'],
            "location" => $booking['location'],
            "contact" => $booking['contact']
        ],

        "owner" => [
            "name" => $booking['owner_name'],
            "phone" => $booking['owner_phone']
        ]
    ]
]);

$stmt->close();
$con->close();

?>