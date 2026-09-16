<?php
header("Content-Type: application/json");
require_once "../connection.php";
require_once "../config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function response(bool $status, string $message, $data = null, int $code = 200): void {
    http_response_code($code);
    $out = ["status" => $status, "message" => $message];
    if ($data !== null) $out["data"] = $data;
    echo json_encode($out);
    exit;
}

function token(): ?string {
    $header = $_SERVER["HTTP_AUTHORIZATION"] ?? "";
    return preg_match("/Bearer\s+(.+)/i", $header, $m) ? trim($m[1]) : null;
}

function auth(array $roles = ["user","owner","admin"]): array {
    global $secret_key;
    $t = token();
    if (!$t) response(false, "Authorization token is required", null, 401);
    try {
        $p = (array)JWT::decode($t, new Key($secret_key, "HS256"));
        if (($p["type"] ?? "") !== "access") response(false, "Invalid access token", null, 401);
        if (!in_array($p["role"] ?? "", $roles, true)) response(false, "Access denied", null, 403);
        return $p;
    } catch (Throwable $e) {
        response(false, "Invalid or expired token", null, 401);
    }
}

if (!isset($con) || $con->connect_error) response(false, "Database connection failed", null, 500);

$user = auth();
$role = $user["role"];
$userId = (int)($user["user_id"] ?? $user["id"] ?? 0);
$method = $_SERVER["REQUEST_METHOD"];
$data = json_decode(file_get_contents("php://input"), true) ?? [];

/* USER: CREATE BOOKING */
if ($method === "POST") {
    if ($role !== "user") response(false, "Only users can create bookings", null, 403);

    $turfId = (int)($data["turf_id"] ?? 0);
    $slotId = (int)($data["slot_id"] ?? 0);
    $bookingDate = trim($data["booking_date"] ?? "");

    if ($turfId <= 0 || $slotId <= 0 || $bookingDate === "")
        response(false, "turf_id, slot_id and booking_date are required", null, 422);

    $d = DateTime::createFromFormat("Y-m-d", $bookingDate);
    if (!$d || $d->format("Y-m-d") !== $bookingDate)
        response(false, "Invalid booking date. Use YYYY-MM-DD", null, 422);

    $con->begin_transaction();

    try {
        $stmt = $con->prepare(
            "SELECT slot_id, turf_id, date, price, status
             FROM turf_slots
             WHERE slot_id = ? AND turf_id = ?
             LIMIT 1 FOR UPDATE"
        );
        if (!$stmt) throw new Exception($con->error);
        $stmt->bind_param("ii", $slotId, $turfId);
        $stmt->execute();
        $r = $stmt->get_result();
        if ($r->num_rows === 0) throw new Exception("Selected slot not found");
        $slot = $r->fetch_assoc();
        $stmt->close();

        if (!empty($slot["date"]) && $slot["date"] !== $bookingDate)
            throw new Exception("Selected slot is not for this date");

        if (strtolower((string)$slot["status"]) !== "available")
            throw new Exception("Selected slot is already unavailable");

        $check = $con->prepare(
            "SELECT booking_id FROM bookings
             WHERE turf_id = ? AND slot_id = ? AND booking_date = ?
             AND status IN ('pending','confirmed','paid')
             LIMIT 1 FOR UPDATE"
        );
        if (!$check) throw new Exception($con->error);
        $check->bind_param("iis", $turfId, $slotId, $bookingDate);
        $check->execute();
        if ($check->get_result()->num_rows > 0)
            throw new Exception("This slot is already booked");
        $check->close();

        $amount = (float)$slot["price"];
        $status = "pending";

        $insert = $con->prepare(
            "INSERT INTO bookings
             (user_id,turf_id,slot_id,booking_date,amount,status)
             VALUES (?,?,?,?,?,?)"
        );
        if (!$insert) throw new Exception($con->error);
        $insert->bind_param("iiisds", $userId, $turfId, $slotId, $bookingDate, $amount, $status);
        if (!$insert->execute()) throw new Exception($insert->error);
        $bookingId = $insert->insert_id;
        $insert->close();

        $slotUpdate = $con->prepare("UPDATE turf_slots SET status='booked' WHERE slot_id=?");
        if (!$slotUpdate) throw new Exception($con->error);
        $slotUpdate->bind_param("i", $slotId);
        if (!$slotUpdate->execute()) throw new Exception($slotUpdate->error);
        $slotUpdate->close();

        $con->commit();

        response(true, "Booking created successfully", [
            "booking_id" => (int)$bookingId,
            "user_id" => $userId,
            "turf_id" => $turfId,
            "slot_id" => $slotId,
            "booking_date" => $bookingDate,
            "amount" => $amount,
            "status" => $status
        ], 201);
    } catch (Throwable $e) {
        $con->rollback();
        response(false, $e->getMessage(), null, 409);
    }
}

/* GET: USER OWN / OWNER OWN TURFS / ADMIN ALL */
if ($method === "GET") {
    if ($role === "user") {
        $stmt = $con->prepare(
            "SELECT b.*, t.turf_name, t.location, ts.start_time, ts.end_time
             FROM bookings b
             JOIN turf_tb t ON t.turf_id=b.turf_id
             JOIN turf_slots ts ON ts.slot_id=b.slot_id
             WHERE b.user_id=?
             ORDER BY b.booking_date DESC, ts.start_time DESC"
        );
        if (!$stmt) response(false, "Failed to prepare booking list", null, 500);
        $stmt->bind_param("i", $userId);
    } elseif ($role === "owner") {
        $stmt = $con->prepare(
            "SELECT b.*, t.turf_name, t.location, ts.start_time, ts.end_time
             FROM bookings b
             JOIN turf_tb t ON t.turf_id=b.turf_id
             JOIN turf_slots ts ON ts.slot_id=b.slot_id
             WHERE t.owner_id=?
             ORDER BY b.booking_date DESC, ts.start_time DESC"
        );
        if (!$stmt) response(false, "Failed to prepare booking list", null, 500);
        $stmt->bind_param("i", $userId);
    } else {
        $stmt = $con->prepare(
            "SELECT b.*, t.turf_name, t.location, ts.start_time, ts.end_time
             FROM bookings b
             JOIN turf_tb t ON t.turf_id=b.turf_id
             JOIN turf_slots ts ON ts.slot_id=b.slot_id
             ORDER BY b.booking_date DESC, ts.start_time DESC"
        );
        if (!$stmt) response(false, "Failed to prepare booking list", null, 500);
    }

    $stmt->execute();
    $r = $stmt->get_result();
    $items = [];
    while ($row = $r->fetch_assoc()) $items[] = $row;
    $stmt->close();
    response(true, "Bookings fetched successfully", $items);
}

/* OWNER / ADMIN: UPDATE STATUS */
if ($method === "PATCH" || $method === "PUT") {
    if (!in_array($role, ["owner","admin"], true))
        response(false, "Only owner or admin can update bookings", null, 403);

    $bookingId = (int)($data["booking_id"] ?? 0);
    $status = strtolower(trim($data["status"] ?? ""));
    $allowed = ["pending","confirmed","paid","cancelled","completed"];

    if ($bookingId <= 0 || !in_array($status, $allowed, true))
        response(false, "Valid booking_id and status are required", null, 422);

    if ($role === "owner") {
        $stmt = $con->prepare(
            "UPDATE bookings b JOIN turf_tb t ON t.turf_id=b.turf_id
             SET b.status=? WHERE b.booking_id=? AND t.owner_id=?"
        );
        if (!$stmt) response(false, "Failed to prepare update", null, 500);
        $stmt->bind_param("sii", $status, $bookingId, $userId);
    } else {
        $stmt = $con->prepare("UPDATE bookings SET status=? WHERE booking_id=?");
        if (!$stmt) response(false, "Failed to prepare update", null, 500);
        $stmt->bind_param("si", $status, $bookingId);
    }

    if (!$stmt->execute()) response(false, "Failed to update booking", null, 500);
    if ($stmt->affected_rows === 0) {
        $stmt->close();
        response(false, "Booking not found or access denied", null, 404);
    }
    $stmt->close();

    if ($status === "cancelled") {
        $slot = $con->prepare(
            "UPDATE turf_slots ts JOIN bookings b ON b.slot_id=ts.slot_id
             SET ts.status='available' WHERE b.booking_id=?"
        );
        if ($slot) {
            $slot->bind_param("i", $bookingId);
            $slot->execute();
            $slot->close();
        }
    }

    response(true, "Booking status updated successfully");
}

/* USER: CANCEL OWN BOOKING */
if ($method === "DELETE") {
    if ($role !== "user") response(false, "Only users can cancel their own bookings", null, 403);

    $bookingId = (int)($data["booking_id"] ?? $_GET["booking_id"] ?? 0);
    if ($bookingId <= 0) response(false, "booking_id is required", null, 422);

    $con->begin_transaction();

    try {
        $stmt = $con->prepare(
            "SELECT slot_id,status FROM bookings
             WHERE booking_id=? AND user_id=? LIMIT 1 FOR UPDATE"
        );
        if (!$stmt) throw new Exception($con->error);
        $stmt->bind_param("ii", $bookingId, $userId);
        $stmt->execute();
        $r = $stmt->get_result();
        if ($r->num_rows === 0) throw new Exception("Booking not found");
        $b = $r->fetch_assoc();
        $stmt->close();

        if (!in_array(strtolower($b["status"]), ["pending","confirmed"], true))
            throw new Exception("This booking cannot be cancelled");

        $u = $con->prepare("UPDATE bookings SET status='cancelled' WHERE booking_id=? AND user_id=?");
        if (!$u) throw new Exception($con->error);
        $u->bind_param("ii", $bookingId, $userId);
        $u->execute();
        $u->close();

        $s = $con->prepare("UPDATE turf_slots SET status='available' WHERE slot_id=?");
        if (!$s) throw new Exception($con->error);
        $slotId = (int)$b["slot_id"];
        $s->bind_param("i", $slotId);
        $s->execute();
        $s->close();

        $con->commit();
        response(true, "Booking cancelled successfully");
    } catch (Throwable $e) {
        $con->rollback();
        response(false, $e->getMessage(), null, 409);
    }
}

response(false, "Unsupported request", null, 405);
?>