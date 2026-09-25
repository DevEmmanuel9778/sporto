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

function authenticate(array $allowedRoles = []): array
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

        if ($allowedRoles !== [] && !in_array($role, $allowedRoles, true)) {
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

    $id = isset($_GET["turf_id"]) ? (int)$_GET["turf_id"] : 0;

    if ($id > 0) {
        $stmt = $con->prepare(
            "SELECT turf_id, owner_id, turf_name, location, price, status
             FROM turf_tb
             WHERE turf_id = ?
             LIMIT 1"
        );

        if (!$stmt) {
            response(false, "Database query failed", [], 500);
        }

        $stmt->bind_param("i", $id);
    } else {
        $stmt = $con->prepare(
            "SELECT turf_id, owner_id, turf_name, location, price, status
             FROM turf_tb
             WHERE status != 'deleted'
             ORDER BY turf_id DESC"
        );

        if (!$stmt) {
            response(false, "Database query failed", [], 500);
        }
    }

    $stmt->execute();
    $result = $stmt->get_result();

    $turfs = [];

    while ($row = $result->fetch_assoc()) {
        $row["turf_id"] = (int)$row["turf_id"];
        $row["owner_id"] = (int)$row["owner_id"];
        $row["price"] = (float)$row["price"];
        $turfs[] = $row;
    }

    $stmt->close();

    response(true, "Turfs fetched successfully", [
        "turfs" => $turfs
    ]);
}

$user = authenticate(["owner", "admin"]);
$role = $user["role"] ?? "";
$userId = (int)($user["user_id"] ?? $user["id"] ?? 0);

$data = inputData();

if ($method === "POST") {
    if ($role !== "owner" && $role !== "admin") {
        response(false, "Only owner or admin can add turf", [], 403);
    }

    $turfName = trim($data["turf_name"] ?? "");
    $location = trim($data["location"] ?? "");
    $price = (float)($data["price"] ?? 0);
    $ownerId = $role === "owner"
        ? $userId
        : (int)($data["owner_id"] ?? 0);

    if ($turfName === "" || $location === "" || $price <= 0 || $ownerId <= 0) {
        response(false, "turf_name, location, price and owner_id are required", [], 422);
    }

    $status = trim($data["status"] ?? "active");

    $stmt = $con->prepare(
        "INSERT INTO turf_tb
        (owner_id, turf_name, location, price, status)
        VALUES (?, ?, ?, ?, ?)"
    );

    if (!$stmt) {
        response(false, "Failed to prepare turf insert", [], 500);
    }

    $stmt->bind_param(
        "issds",
        $ownerId,
        $turfName,
        $location,
        $price,
        $status
    );

    if (!$stmt->execute()) {
        response(false, "Failed to add turf", [], 500);
    }

    $newId = $stmt->insert_id;
    $stmt->close();

    response(true, "Turf added successfully", [
        "turf_id" => $newId
    ], 201);
}

if ($method === "PUT" || $method === "PATCH") {
    $turfId = (int)($data["turf_id"] ?? 0);

    if ($turfId <= 0) {
        response(false, "turf_id is required", [], 422);
    }

    if ($role === "owner") {
        $check = $con->prepare(
            "SELECT turf_id
             FROM turf_tb
             WHERE turf_id = ? AND owner_id = ?
             LIMIT 1"
        );

        if (!$check) {
            response(false, "Database query failed", [], 500);
        }

        $check->bind_param("ii", $turfId, $userId);
        $check->execute();

        if ($check->get_result()->num_rows === 0) {
            $check->close();
            response(false, "You can update only your own turf", [], 403);
        }

        $check->close();
    }

    $fields = [];
    $types = "";
    $values = [];

    if (array_key_exists("turf_name", $data)) {
        $fields[] = "turf_name = ?";
        $types .= "s";
        $values[] = trim($data["turf_name"]);
    }

    if (array_key_exists("location", $data)) {
        $fields[] = "location = ?";
        $types .= "s";
        $values[] = trim($data["location"]);
    }

    if (array_key_exists("price", $data)) {
        $fields[] = "price = ?";
        $types .= "d";
        $values[] = (float)$data["price"];
    }

    if (array_key_exists("status", $data)) {
        $fields[] = "status = ?";
        $types .= "s";
        $values[] = trim($data["status"]);
    }

    if ($role === "admin" && array_key_exists("owner_id", $data)) {
        $fields[] = "owner_id = ?";
        $types .= "i";
        $values[] = (int)$data["owner_id"];
    }

    if ($fields === []) {
        response(false, "No fields to update", [], 422);
    }

    $sql = "UPDATE turf_tb SET " . implode(", ", $fields) . " WHERE turf_id = ?";
    $types .= "i";
    $values[] = $turfId;

    $stmt = $con->prepare($sql);

    if (!$stmt) {
        response(false, "Failed to prepare turf update", [], 500);
    }

    $stmt->bind_param($types, ...$values);

    if (!$stmt->execute()) {
        response(false, "Failed to update turf", [], 500);
    }

    $stmt->close();

    response(true, "Turf updated successfully");
}

if ($method === "DELETE") {
    $turfId = (int)($data["turf_id"] ?? $_GET["turf_id"] ?? 0);

    if ($turfId <= 0) {
        response(false, "turf_id is required", [], 422);
    }

    if ($role === "owner") {
        $check = $con->prepare(
            "SELECT turf_id
             FROM turf_tb
             WHERE turf_id = ? AND owner_id = ?
             LIMIT 1"
        );

        if (!$check) {
            response(false, "Database query failed", [], 500);
        }

        $check->bind_param("ii", $turfId, $userId);
        $check->execute();

        if ($check->get_result()->num_rows === 0) {
            $check->close();
            response(false, "You can delete only your own turf", [], 403);
        }

        $check->close();
    }

    /*
     * Do not physically delete a turf when bookings already exist.
     * Mark it deleted instead, so booking history is preserved.
     *
     * This uses bookings.turf_id. If your bookings table uses another
     * column name, change this query to match your actual structure.
     */
    $bookingCheck = $con->prepare(
        "SELECT COUNT(*) AS total
         FROM bookings
         WHERE turf_id = ?"
    );

    if (!$bookingCheck) {
        response(false, "Could not check turf bookings. Verify bookings.turf_id exists.", [], 500);
    }

    $bookingCheck->bind_param("i", $turfId);
    $bookingCheck->execute();

    $bookingResult = $bookingCheck->get_result()->fetch_assoc();
    $bookingCount = (int)($bookingResult["total"] ?? 0);

    $bookingCheck->close();

    if ($bookingCount > 0) {
        $stmt = $con->prepare(
            "UPDATE turf_tb
             SET status = 'deleted'
             WHERE turf_id = ?"
        );

        if (!$stmt) {
            response(false, "Failed to prepare turf delete", [], 500);
        }

        $stmt->bind_param("i", $turfId);
        $stmt->execute();
        $stmt->close();

        response(true, "Turf marked as deleted because booking history exists");
    }

    $stmt = $con->prepare(
        "DELETE FROM turf_tb
         WHERE turf_id = ?"
    );

    if (!$stmt) {
        response(false, "Failed to prepare turf delete", [], 500);
    }

    $stmt->bind_param("i", $turfId);

    if (!$stmt->execute()) {
        response(false, "Failed to delete turf", [], 500);
    }

    $stmt->close();

    response(true, "Turf deleted successfully");
}

response(false, "Unsupported request method", [], 405);
?>
