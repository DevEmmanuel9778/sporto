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

$bookingId = (int)($data['booking_id'] ?? 0);

if ($bookingId <= 0) {
    echo json_encode([
        "status" => false,
        "message" => "Valid booking ID is required"
    ]);
    exit;
}

$con->begin_transaction();

try {

    /*
     * Find booking belonging to this user.
     */
    $bookingStmt = $con->prepare(
        "SELECT
            id,
            slot_id,
            status
         FROM bookings
         WHERE id = ?
         AND user_id = ?
         LIMIT 1
         FOR UPDATE"
    );

    $bookingStmt->bind_param(
        "ii",
        $bookingId,
        $userId
    );

    $bookingStmt->execute();

    $bookingResult = $bookingStmt->get_result();

    if ($bookingResult->num_rows === 0) {

        throw new Exception(
            "Booking not found"
        );
    }

    $booking = $bookingResult->fetch_assoc();

    if (
        $booking['status'] === 'cancelled'
    ) {

        throw new Exception(
            "Booking is already cancelled"
        );
    }

    if (
        $booking['status'] === 'completed'
    ) {

        throw new Exception(
            "Completed booking cannot be cancelled"
        );
    }

    /*
     * Cancel booking.
     */
    $cancelStmt = $con->prepare(
        "UPDATE bookings
         SET status = 'cancelled'
         WHERE id = ?
         AND user_id = ?"
    );

    $cancelStmt->bind_param(
        "ii",
        $bookingId,
        $userId
    );

    if (!$cancelStmt->execute()) {

        throw new Exception(
            "Failed to cancel booking"
        );
    }

    /*
     * Make the slot available again.
     */
    $slotStmt = $con->prepare(
        "UPDATE turf_slots
         SET status = 'available'
         WHERE id = ?"
    );

    $slotStmt->bind_param(
        "i",
        $booking['slot_id']
    );

    if (!$slotStmt->execute()) {

        throw new Exception(
            "Failed to release turf slot"
        );
    }

    $slotStmt->close();
    $cancelStmt->close();
    $bookingStmt->close();

    $con->commit();

    echo json_encode([
        "status" => true,
        "message" => "Booking cancelled successfully"
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