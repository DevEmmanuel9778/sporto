<?php

header("Content-Type: application/json");

require_once "../connection.php";
require_once "../config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function response(bool $status, string $message, array $data = [], int $code = 200): never
{
    http_response_code($code);

    echo json_encode([
        "status" => $status,
        "message" => $message,
        ...$data
    ]);

    exit;
}

function getBearerToken(): ?string
{
    $headers = function_exists("getallheaders") ? getallheaders() : [];

    $authorization = $headers["Authorization"]
        ?? $headers["authorization"]
        ?? ($_SERVER["HTTP_AUTHORIZATION"] ?? null);

    if (!$authorization || !preg_match("/Bearer\s+(.+)/i", $authorization, $matches)) {
        return null;
    }

    return trim($matches[1]);
}

function authenticate(array $allowedRoles): array
{
    global $secret_key;

    $token = getBearerToken();

    if (!$token) {
        response(false, "Authorization token is required", [], 401);
    }

    try {
        $decoded = JWT::decode($token, new Key($secret_key, "HS256"));
        $payload = (array)$decoded;

        if (($payload["type"] ?? "") !== "access") {
            response(false, "Invalid access token", [], 401);
        }

        $role = $payload["role"] ?? "";

        if (!in_array($role, $allowedRoles, true)) {
            response(false, "You do not have permission for this action", [], 403);
        }

        return $payload;
    } catch (Throwable $e) {
        response(false, "Invalid or expired token", [], 401);
    }
}

function inputData(): array
{
    $raw = file_get_contents("php://input");
    $data = json_decode($raw, true);

    return is_array($data) ? $data : $_POST;
}

$method = $_SERVER["REQUEST_METHOD"];

if ($method === "GET") {
    authenticate(["user", "owner", "admin"]);

    $turfId = (int)($_GET["turf_id"] ?? 0);
    $date = trim($_GET["date"] ?? "");

    $sql = "
        SELECT
            ts.slot_id,
            ts.turf_id,
            ts.date,
            ts.start_time,
            ts.end_time,
            ts.price,
            CASE
                WHEN EXISTS (
                    SELECT 1
                    FROM bookings b
                    WHERE b.slot_id = ts.slot_id
                      AND b.status IN ('pending', 'confirmed', 'paid')
                )
                THEN 'booked'
                ELSE ts.status
            END AS status
        FROM turf_slots ts
        WHERE 1 = 1
    ";

    $types = "";
    $values = [];

    if ($turfId > 0) {
        $sql .= " AND ts.turf_id = ?";
        $types .= "i";
        $values[] = $turfId;
    }

    if ($date !== "") {
        $sql .= " AND ts.date = ?";
        $types .= "s";
        $values[] = $date;
    }

    $sql .= " ORDER BY ts.date ASC, ts.start_time ASC";

    $stmt = $con->prepare($sql);

    if (!$stmt) {
        response(false, "Slot query failed. Verify bookings.slot_id and bookings.status.", [], 500);
    }

    if ($types !== "") {
        $stmt->bind_param($types, ...$values);
    }

    $stmt->execute();
    $result = $stmt->get_result();

    $slots = [];

    while ($row = $result->fetch_assoc()) {
        $row["slot_id"] = (int)$row["slot_id"];
        $row["turf_id"] = (int)$row["turf_id"];
        $row["price"] = (float)$row["price"];
        $slots[] = $row;
    }

    $stmt->close();

    response(true, "Slots fetched successfully", [
        "slots" => $slots
    ]);
}

$user = authenticate(["owner", "admin"]);
$role = $user["role"] ?? "";
$userId = (int)($user["user_id"] ?? $user["id"] ?? 0);

$data = inputData();

function verifyTurfPermission(mysqli $con, int $turfId, string $role, int $userId): void
{
    if ($turfId <= 0) {
        response(false, "turf_id is required", [], 422);
    }

    if ($role !== "owner") {
        return;
    }

    $stmt = $con->prepare(
        "SELECT turf_id
         FROM turf_tb
         WHERE turf_id = ? AND owner_id = ?
         LIMIT 1"
    );

    if (!$stmt) {
        response(false, "Database query failed", [], 500);
    }

    $stmt->bind_param("ii", $turfId, $userId);
    $stmt->execute();

    if ($stmt->get_result()->num_rows === 0) {
        $stmt->close();
        response(false, "You can manage slots only for your own turf", [], 403);
    }

    $stmt->close();
}

if ($method === "POST") {
    $turfId = (int)($data["turf_id"] ?? 0);

    verifyTurfPermission($con, $turfId, $role, $userId);

    $date = trim($data["date"] ?? "");
    $startTime = trim($data["start_time"] ?? "");
    $endTime = trim($data["end_time"] ?? "");
    $price = (float)($data["price"] ?? 0);
    $status = trim($data["status"] ?? "available");

    if ($date === "" || $startTime === "" || $endTime === "" || $price <= 0) {
        response(false, "date, start_time, end_time and price are required", [], 422);
    }

    $stmt = $con->prepare(
        "INSERT INTO turf_slots
        (turf_id, date, start_time, end_time, price, status)
        VALUES (?, ?, ?, ?, ?, ?)"
    );

    if (!$stmt) {
        response(false, "Failed to prepare slot insert", [], 500);
    }

    $stmt->bind_param(
        "isssds",
        $turfId,
        $date,
        $startTime,
        $endTime,
        $price,
        $status
    );

    if (!$stmt->execute()) {
        response(false, "Failed to add slot", [], 500);
    }

    $slotId = $stmt->insert_id;
    $stmt->close();

    response(true, "Slot added successfully", [
        "slot_id" => $slotId
    ], 201);
}

if ($method === "PUT" || $method === "PATCH") {
    $slotId = (int)($data["slot_id"] ?? 0);

    if ($slotId <= 0) {
        response(false, "slot_id is required", [], 422);
    }

    $check = $con->prepare(
        "SELECT turf_id
         FROM turf_slots
         WHERE slot_id = ?
         LIMIT 1"
    );

    if (!$check) {
        response(false, "Database query failed", [], 500);
    }

    $check->bind_param("i", $slotId);
    $check->execute();
    $slot = $check->get_result()->fetch_assoc();
    $check->close();

    if (!$slot) {
        response(false, "Slot not found", [], 404);
    }

    $turfId = (int)$slot["turf_id"];

    verifyTurfPermission($con, $turfId, $role, $userId);

    /*
     * A booked slot must not be edited.
     */
    $bookingCheck = $con->prepare(
        "SELECT COUNT(*) AS total
         FROM bookings
         WHERE slot_id = ?
           AND status IN ('pending', 'confirmed', 'paid')"
    );

    if (!$bookingCheck) {
        response(false, "Could not check booking status. Verify bookings.slot_id and bookings.status.", [], 500);
    }

    $bookingCheck->bind_param("i", $slotId);
    $bookingCheck->execute();

    $bookingCount = (int)(
        $bookingCheck->get_result()->fetch_assoc()["total"] ?? 0
    );

    $bookingCheck->close();

    if ($bookingCount > 0) {
        response(false, "Booked slot cannot be edited", [], 409);
    }

    $fields = [];
    $types = "";
    $values = [];

    foreach ([
        "date" => "s",
        "start_time" => "s",
        "end_time" => "s",
        "price" => "d",
        "status" => "s"
    ] as $field => $type) {
        if (array_key_exists($field, $data)) {
            $fields[] = "$field = ?";
            $types .= $type;
            $values[] = $type === "d"
                ? (float)$data[$field]
                : trim($data[$field]);
        }
    }

    if ($fields === []) {
        response(false, "No fields to update", [], 422);
    }

    $sql = "UPDATE turf_slots SET " . implode(", ", $fields) . " WHERE slot_id = ?";
    $types .= "i";
    $values[] = $slotId;

    $stmt = $con->prepare($sql);

    if (!$stmt) {
        response(false, "Failed to prepare slot update", [], 500);
    }

    $stmt->bind_param($types, ...$values);

    if (!$stmt->execute()) {
        response(false, "Failed to update slot", [], 500);
    }

    $stmt->close();

    response(true, "Slot updated successfully");
}

if ($method === "DELETE") {
    $slotId = (int)($data["slot_id"] ?? $_GET["slot_id"] ?? 0);

    if ($slotId <= 0) {
        response(false, "slot_id is required", [], 422);
    }

    $check = $con->prepare(
        "SELECT turf_id
         FROM turf_slots
         WHERE slot_id = ?
         LIMIT 1"
    );

    if (!$check) {
        response(false, "Database query failed", [], 500);
    }

    $check->bind_param("i", $slotId);
    $check->execute();
    $slot = $check->get_result()->fetch_assoc();
    $check->close();

    if (!$slot) {
        response(false, "Slot not found", [], 404);
    }

    $turfId = (int)$slot["turf_id"];

    verifyTurfPermission($con, $turfId, $role, $userId);

    /*
     * Never delete a slot if it has an active booking.
     */
    $bookingCheck = $con->prepare(
        "SELECT COUNT(*) AS total
         FROM bookings
         WHERE slot_id = ?
           AND status IN ('pending', 'confirmed', 'paid')"
    );

    if (!$bookingCheck) {
        response(false, "Could not check booking status. Verify bookings.slot_id and bookings.status.", [], 500);
    }

    $bookingCheck->bind_param("i", $slotId);
    $bookingCheck->execute();

    $bookingCount = (int)(
        $bookingCheck->get_result()->fetch_assoc()["total"] ?? 0
    );

    $bookingCheck->close();

    if ($bookingCount > 0) {
        response(false, "Booked slot cannot be deleted", [], 409);
    }

    $stmt = $con->prepare(
        "DELETE FROM turf_slots
         WHERE slot_id = ?"
    );

    if (!$stmt) {
        response(false, "Failed to prepare slot delete", [], 500);
    }

    $stmt->bind_param("i", $slotId);

    if (!$stmt->execute()) {
        response(false, "Failed to delete slot", [], 500);
    }

    $stmt->close();

    response(true, "Slot deleted successfully");
}

response(false, "Unsupported request method", [], 405);
?>
