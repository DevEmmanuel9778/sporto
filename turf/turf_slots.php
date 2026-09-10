<?php

header("Content-Type: application/json");

require_once "../connection.php";
require_once "../config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$method = $_SERVER['REQUEST_METHOD'];

function getAccessToken()
{
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? '';

    if ($authHeader === '') {
        return null;
    }

    if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        return null;
    }

    return $matches[1];
}

function verifyToken($token, $secretKey)
{
    try {

        return JWT::decode(
            $token,
            new Key($secretKey, "HS256")
        );

    } catch (Throwable $e) {

        return null;
    }
}

/*
|--------------------------------------------------------------------------
| GET - View Turf Slots
|--------------------------------------------------------------------------
*/

if ($method === 'GET') {

    $turfId = (int)($_GET['turf_id'] ?? 0);

    if ($turfId <= 0) {
        echo json_encode([
            "status" => false,
            "message" => "Valid turf ID is required"
        ]);
        exit;
    }

    $date = trim($_GET['date'] ?? '');

    if ($date !== '') {

        $stmt = $con->prepare(
            "SELECT
                id,
                turf_id,
                date,
                start_time,
                end_time,
                price,
                status
             FROM turf_slots
             WHERE turf_id = ?
             AND date = ?
             AND status = 'available'
             ORDER BY start_time ASC"
        );

        $stmt->bind_param(
            "is",
            $turfId,
            $date
        );

    } else {

        $stmt = $con->prepare(
            "SELECT
                id,
                turf_id,
                date,
                start_time,
                end_time,
                price,
                status
             FROM turf_slots
             WHERE turf_id = ?
             AND status = 'available'
             ORDER BY date ASC, start_time ASC"
        );

        $stmt->bind_param(
            "i",
            $turfId
        );
    }

    $stmt->execute();

    $result = $stmt->get_result();

    $slots = [];

    while ($row = $result->fetch_assoc()) {

        $slots[] = [
            "id" => (int)$row['id'],
            "turf_id" => (int)$row['turf_id'],
            "date" => $row['date'],
            "start_time" => $row['start_time'],
            "end_time" => $row['end_time'],
            "price" => (float)$row['price'],
            "status" => $row['status']
        ];
    }

    echo json_encode([
        "status" => true,
        "message" => "Slots fetched successfully",
        "slots" => $slots
    ]);

    $stmt->close();
    $con->close();

    exit;
}

/*
|--------------------------------------------------------------------------
| POST - Create Turf Slot
|--------------------------------------------------------------------------
*/

if ($method !== 'POST') {

    echo json_encode([
        "status" => false,
        "message" => "Only GET and POST methods are allowed"
    ]);

    exit;
}

$accessToken = getAccessToken();

if ($accessToken === null) {

    echo json_encode([
        "status" => false,
        "message" => "Authorization token is required"
    ]);

    exit;
}

$decoded = verifyToken(
    $accessToken,
    $secret_key
);

if ($decoded === null) {

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
        "message" => "Only turf owners can create slots"
    ]);

    exit;
}

$data = json_decode(
    file_get_contents("php://input"),
    true
);

$turfId = (int)($data['turf_id'] ?? 0);
$date = trim($data['date'] ?? '');
$startTime = trim($data['start_time'] ?? '');
$endTime = trim($data['end_time'] ?? '');
$price = $data['price'] ?? '';

if (
    $turfId <= 0 ||
    $date === '' ||
    $startTime === '' ||
    $endTime === '' ||
    $price === ''
) {

    echo json_encode([
        "status" => false,
        "message" => "All slot fields are required"
    ]);

    exit;
}

if (!is_numeric($price) || $price <= 0) {

    echo json_encode([
        "status" => false,
        "message" => "Invalid slot price"
    ]);

    exit;
}

if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {

    echo json_encode([
        "status" => false,
        "message" => "Invalid date format. Use YYYY-MM-DD"
    ]);

    exit;
}

if (!preg_match('/^\d{2}:\d{2}(:\d{2})?$/', $startTime)) {

    echo json_encode([
        "status" => false,
        "message" => "Invalid start time"
    ]);

    exit;
}

if (!preg_match('/^\d{2}:\d{2}(:\d{2})?$/', $endTime)) {

    echo json_encode([
        "status" => false,
        "message" => "Invalid end time"
    ]);

    exit;
}

if ($startTime >= $endTime) {

    echo json_encode([
        "status" => false,
        "message" => "End time must be after start time"
    ]);

    exit;
}

/*
 * Check turf ownership.
 */
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

/*
 * Check overlapping slot.
 */
$overlapStmt = $con->prepare(
    "SELECT id
     FROM turf_slots
     WHERE turf_id = ?
     AND date = ?
     AND status = 'available'
     AND start_time < ?
     AND end_time > ?
     LIMIT 1"
);

$overlapStmt->bind_param(
    "isss",
    $turfId,
    $date,
    $endTime,
    $startTime
);

$overlapStmt->execute();

$overlapResult = $overlapStmt->get_result();

if ($overlapResult->num_rows > 0) {

    echo json_encode([
        "status" => false,
        "message" => "This time slot overlaps with an existing slot"
    ]);

    exit;
}

$overlapStmt->close();

$status = "available";

$stmt = $con->prepare(
    "INSERT INTO turf_slots
    (
        turf_id,
        date,
        start_time,
        end_time,
        price,
        status
    )
    VALUES (?, ?, ?, ?, ?, ?)"
);

$stmt->bind_param(
    "isssds",
    $turfId,
    $date,
    $startTime,
    $endTime,
    $price,
    $status
);

if ($stmt->execute()) {

    echo json_encode([
        "status" => true,
        "message" => "Turf slot created successfully",
        "slot_id" => $stmt->insert_id
    ]);

} else {

    echo json_encode([
        "status" => false,
        "message" => "Failed to create turf slot"
    ]);
}

$stmt->close();
$con->close();

?>