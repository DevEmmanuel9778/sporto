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
        "message" => "Only users can create bookings"
    ]);
    exit;
}

$data = json_decode(
    file_get_contents("php://input"),
    true
);

$turfId = (int)($data['turf_id'] ?? 0);
$slotId = (int)($data['slot_id'] ?? 0);

if ($turfId <= 0 || $slotId <= 0) {
    echo json_encode([
        "status" => false,
        "message" => "Valid turf ID and slot ID are required"
    ]);
    exit;
}

$con->begin_transaction();

try {

    /*
     * Get slot information.
     */
    $slotStmt = $con->prepare(
        "SELECT
            s.id,
            s.turf_id,
            s.date,
            s.start_time,
            s.end_time,
            s.price,
            s.status,
            t.status AS turf_status
         FROM turf_slots s
         INNER JOIN turfs t
            ON s.turf_id = t.id
         WHERE s.id = ?
         AND s.turf_id = ?
         FOR UPDATE"
    );

    $slotStmt->bind_param(
        "ii",
        $slotId,
        $turfId
    );

    $slotStmt->execute();

    $slotResult = $slotStmt->get_result();

    if ($slotResult->num_rows === 0) {

        throw new Exception("Slot not found");
    }

    $slot = $slotResult->fetch_assoc();

    if ($slot['turf_status'] !== 'active') {

        throw new Exception("Turf is not available");
    }

    if ($slot['status'] !== 'available') {

        throw new Exception("This slot is no longer available");
    }

    /*
     * Check whether this slot is already booked.
     */
    $bookingCheck = $con->prepare(
        "SELECT id
         FROM bookings
         WHERE slot_id = ?
         AND status IN ('pending', 'confirmed')
         LIMIT 1"
    );

    $bookingCheck->bind_param(
        "i",
        $slotId
    );

    $bookingCheck->execute();

    $bookingResult = $bookingCheck->get_result();

    if ($bookingResult->num_rows > 0) {

        throw new Exception(
            "This slot has already been booked"
        );
    }

    $bookingCheck->close();

    /*
     * Create booking.
     */
    $bookingDate = $slot['date'];
    $amount = (float)$slot['price'];
    $status = "pending";

    $bookingStmt = $con->prepare(
        "INSERT INTO bookings
        (
            user_id,
            turf_id,
            slot_id,
            booking_date,
            amount,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?)"
    );

    $bookingStmt->bind_param(
        "iiisds",
        $userId,
        $turfId,
        $slotId,
        $bookingDate,
        $amount,
        $status
    );

    if (!$bookingStmt->execute()) {

        throw new Exception(
            "Failed to create booking"
        );
    }

    $bookingId = $bookingStmt->insert_id;

    /*
     * Temporarily mark slot as booked.
     */
    $updateSlot = $con->prepare(
        "UPDATE turf_slots
         SET status = 'booked'
         WHERE id = ?
         AND status = 'available'"
    );

    $updateSlot->bind_param(
        "i",
        $slotId
    );

    $updateSlot->execute();

    if ($updateSlot->affected_rows === 0) {

        throw new Exception(
            "Slot is no longer available"
        );
    }

    $updateSlot->close();
    $bookingStmt->close();
    $slotStmt->close();

    $con->commit();

    echo json_encode([
        "status" => true,
        "message" => "Booking created successfully",
        "booking" => [
            "id" => $bookingId,
            "user_id" => $userId,
            "turf_id" => $turfId,
            "slot_id" => $slotId,
            "booking_date" => $bookingDate,
            "start_time" => $slot['start_time'],
            "end_time" => $slot['end_time'],
            "amount" => $amount,
            "status" => $status
        ]
    ]);

} catch (Throwable $e) {

    $con->rollback();

    echo json_encode([
        "status" => false,
        "message" => $e->getMessage()
    ]);
}

$con->close();

?>