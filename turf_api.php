<?php

ini_set("display_errors", "0");
ini_set("log_errors", "1");
error_reporting(E_ALL);

header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Max-Age: 86400");

if (($_SERVER["REQUEST_METHOD"] ?? "") === "OPTIONS") {
    http_response_code(204);
    exit;
}

require_once __DIR__ . "/connection.php";
require_once __DIR__ . "/config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
// =========================
// RESPONSE HELPER
// =========================
function response(
    bool $status,
    string $message,
    array $data = [],
    int $code = 200
): never {
    http_response_code($code);

    echo json_encode(
        [
            "status" => $status,
            "message" => $message,
            ...$data,
        ],
        JSON_UNESCAPED_UNICODE
    );

    exit;
}

// =========================
// GET BEARER TOKEN
// =========================
function getBearerToken(): ?string
{
    $authorization = null;

    if (function_exists("getallheaders")) {
        $headers = getallheaders();

        foreach ($headers as $key => $value) {
            if (strtolower($key) === "authorization") {
                $authorization = $value;
                break;
            }
        }
    }

    if (!$authorization) {
        $authorization = $_SERVER["HTTP_AUTHORIZATION"] ?? null;
    }

    if (
        !$authorization ||
        !preg_match("/Bearer\s+(.+)/i", $authorization, $matches)
    ) {
        return null;
    }

    return trim($matches[1]);
}

// =========================
// AUTHENTICATION
// =========================
function authenticate(array $allowedRoles = []): array
{
    global $secret_key;

    $token = getBearerToken();

    if (!$token) {
        response(
            false,
            "Authorization token is required",
            [],
            401
        );
    }

    try {
        $decoded = JWT::decode(
            $token,
            new Key($secret_key, "HS256")
        );

        $payload = (array) $decoded;

        if (($payload["type"] ?? "") !== "access") {
            response(
                false,
                "Invalid access token",
                [],
                401
            );
        }

        $role = (string) ($payload["role"] ?? "");

        if (
            $allowedRoles !== [] &&
            !in_array($role, $allowedRoles, true)
        ) {
            response(
                false,
                "You do not have permission for this action",
                [],
                403
            );
        }

        return $payload;

    } catch (Throwable $e) {
        response(
            false,
            "Invalid or expired token",
            [],
            401
        );
    }
}

// =========================
// INPUT DATA
// =========================
function inputData(): array
{
    $raw = file_get_contents("php://input");

    if ($raw !== false && trim($raw) !== "") {
        $data = json_decode($raw, true);

        if (is_array($data)) {
            return $data;
        }
    }

    return is_array($_POST) ? $_POST : [];
}

// =========================
// REQUEST METHOD
// =========================
$method = strtoupper($_SERVER["REQUEST_METHOD"] ?? "GET");

// =========================
// GET TURFS
// =========================
if ($method === "GET") {
    authenticate(["user", "owner", "admin"]);

    $id = isset($_GET["turf_id"])
        ? (int) $_GET["turf_id"]
        : 0;

    // -------------------------
    // Single turf
    // -------------------------
    if ($id > 0) {
        $stmt = $con->prepare(
            "SELECT
                turf_id,
                owner_id,
                turf_name,
                location,
                price,
                status
             FROM turf_tb
             WHERE turf_id = ?
             LIMIT 1"
        );

        if (!$stmt) {
            response(
                false,
                "Database query failed",
                [],
                500
            );
        }

        $stmt->bind_param("i", $id);

    // -------------------------
    // All turfs
    // -------------------------
    } else {
        $stmt = $con->prepare(
            "SELECT
                turf_id,
                owner_id,
                turf_name,
                location,
                price,
                status
             FROM turf_tb
             WHERE status != 'deleted'
             ORDER BY turf_id DESC"
        );

        if (!$stmt) {
            response(
                false,
                "Database query failed",
                [],
                500
            );
        }
    }

    if (!$stmt->execute()) {
        $stmt->close();

        response(
            false,
            "Failed to fetch turfs",
            [],
            500
        );
    }

    $result = $stmt->get_result();

    $turfs = [];

    while ($row = $result->fetch_assoc()) {
        $turfs[] = [
            "turf_id" => (int) ($row["turf_id"] ?? 0),
            "owner_id" => (int) ($row["owner_id"] ?? 0),
            "turf_name" => (string) ($row["turf_name"] ?? ""),
            "location" => (string) ($row["location"] ?? ""),
            "price" => (float) ($row["price"] ?? 0),
            "status" => (string) ($row["status"] ?? ""),
        ];
    }

    $stmt->close();

    response(
        true,
        "Turfs fetched successfully",
        [
            "turfs" => $turfs,
        ]
    );
}

// =========================
// AUTH FOR WRITE ACTIONS
// =========================
$user = authenticate(["owner", "admin"]);

$role = (string) ($user["role"] ?? "");

$userId = (int) (
    $user["user_id"]
    ?? $user["id"]
    ?? 0
);

$data = inputData();

// =========================
// POST - ADD TURF
// =========================
if ($method === "POST") {

    $turfName = trim(
        (string) ($data["turf_name"] ?? "")
    );

    $location = trim(
        (string) ($data["location"] ?? "")
    );

    $price = (float) (
        $data["price"] ?? 0
    );

    $ownerId = $role === "owner"
        ? $userId
        : (int) ($data["owner_id"] ?? 0);

    $status = trim(
        (string) ($data["status"] ?? "active")
    );

    // -------------------------
    // Validation
    // -------------------------
    if ($turfName === "") {
        response(
            false,
            "Turf name is required",
            [],
            422
        );
    }

    if ($location === "") {
        response(
            false,
            "Location is required",
            [],
            422
        );
    }

    if ($price <= 0) {
        response(
            false,
            "Price must be greater than 0",
            [],
            422
        );
    }

    if ($ownerId <= 0) {
        response(
            false,
            "Valid owner_id is required",
            [],
            422
        );
    }

    $allowedStatuses = [
        "active",
        "inactive",
        "deleted",
    ];

    if (!in_array($status, $allowedStatuses, true)) {
        $status = "active";
    }

    // -------------------------
    // Insert
    // -------------------------
    $stmt = $con->prepare(
        "INSERT INTO turf_tb
        (
            owner_id,
            turf_name,
            location,
            price,
            status
        )
        VALUES (?, ?, ?, ?, ?)"
    );

    if (!$stmt) {
        response(
            false,
            "Failed to prepare turf insert",
            [],
            500
        );
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
        $error = $stmt->error;
        $stmt->close();

        response(
            false,
            "Failed to add turf: " . $error,
            [],
            500
        );
    }

    $newId = (int) $stmt->insert_id;

    $stmt->close();

    response(
        true,
        "Turf added successfully",
        [
            "turf_id" => $newId,
        ],
        201
    );
}

// =========================
// PUT / PATCH - UPDATE TURF
// =========================
if ($method === "PUT" || $method === "PATCH") {

    $turfId = (int) (
        $data["turf_id"] ?? 0
    );

    if ($turfId <= 0) {
        response(
            false,
            "turf_id is required",
            [],
            422
        );
    }

    // -------------------------
    // Owner ownership check
    // -------------------------
    if ($role === "owner") {

        $check = $con->prepare(
            "SELECT turf_id
             FROM turf_tb
             WHERE turf_id = ?
               AND owner_id = ?
             LIMIT 1"
        );

        if (!$check) {
            response(
                false,
                "Database query failed",
                [],
                500
            );
        }

        $check->bind_param(
            "ii",
            $turfId,
            $userId
        );

        if (!$check->execute()) {
            $check->close();

            response(
                false,
                "Failed to verify turf ownership",
                [],
                500
            );
        }

        $result = $check->get_result();

        if ($result->num_rows === 0) {
            $check->close();

            response(
                false,
                "You can update only your own turf",
                [],
                403
            );
        }

        $check->close();
    }

    // -------------------------
    // Build update query
    // -------------------------
    $fields = [];
    $types = "";
    $values = [];

    if (array_key_exists("turf_name", $data)) {
        $name = trim(
            (string) $data["turf_name"]
        );

        if ($name === "") {
            response(
                false,
                "Turf name cannot be empty",
                [],
                422
            );
        }

        $fields[] = "turf_name = ?";
        $types .= "s";
        $values[] = $name;
    }

    if (array_key_exists("location", $data)) {
        $locationValue = trim(
            (string) $data["location"]
        );

        if ($locationValue === "") {
            response(
                false,
                "Location cannot be empty",
                [],
                422
            );
        }

        $fields[] = "location = ?";
        $types .= "s";
        $values[] = $locationValue;
    }

    if (array_key_exists("price", $data)) {
        $priceValue = (float) $data["price"];

        if ($priceValue <= 0) {
            response(
                false,
                "Price must be greater than 0",
                [],
                422
            );
        }

        $fields[] = "price = ?";
        $types .= "d";
        $values[] = $priceValue;
    }

    if (array_key_exists("status", $data)) {
        $statusValue = trim(
            (string) $data["status"]
        );

        $allowedStatuses = [
            "active",
            "inactive",
            "deleted",
        ];

        if (!in_array($statusValue, $allowedStatuses, true)) {
            response(
                false,
                "Invalid turf status",
                [],
                422
            );
        }

        $fields[] = "status = ?";
        $types .= "s";
        $values[] = $statusValue;
    }

    if (
        $role === "admin" &&
        array_key_exists("owner_id", $data)
    ) {
        $ownerValue = (int) $data["owner_id"];

        if ($ownerValue <= 0) {
            response(
                false,
                "Invalid owner_id",
                [],
                422
            );
        }

        $fields[] = "owner_id = ?";
        $types .= "i";
        $values[] = $ownerValue;
    }

    if ($fields === []) {
        response(
            false,
            "No fields to update",
            [],
            422
        );
    }

    $sql =
        "UPDATE turf_tb SET "
        . implode(", ", $fields)
        . " WHERE turf_id = ?";

    $types .= "i";
    $values[] = $turfId;

    $stmt = $con->prepare($sql);

    if (!$stmt) {
        response(
            false,
            "Failed to prepare turf update",
            [],
            500
        );
    }

    // mysqli bind_param needs references.
    $bindValues = [];

    foreach ($values as $key => $value) {
        $bindValues[$key] = $value;
    }

    $references = [];

    foreach ($bindValues as $key => &$value) {
        $references[$key] = &$value;
    }

    array_unshift(
        $references,
        $types
    );

    if (!call_user_func_array(
        [$stmt, "bind_param"],
        $references
    )) {
        $stmt->close();

        response(
            false,
            "Failed to bind turf update parameters",
            [],
            500
        );
    }

    if (!$stmt->execute()) {
        $error = $stmt->error;
        $stmt->close();

        response(
            false,
            "Failed to update turf: " . $error,
            [],
            500
        );
    }

    $stmt->close();

    response(
        true,
        "Turf updated successfully"
    );
}

// =========================
// DELETE TURF
// =========================
if ($method === "DELETE") {

    $turfId = (int) (
        $data["turf_id"]
        ?? $_GET["turf_id"]
        ?? 0
    );

    if ($turfId <= 0) {
        response(
            false,
            "turf_id is required",
            [],
            422
        );
    }

    // -------------------------
    // Owner ownership check
    // -------------------------
    if ($role === "owner") {

        $check = $con->prepare(
            "SELECT turf_id
             FROM turf_tb
             WHERE turf_id = ?
               AND owner_id = ?
             LIMIT 1"
        );

        if (!$check) {
            response(
                false,
                "Database query failed",
                [],
                500
            );
        }

        $check->bind_param(
            "ii",
            $turfId,
            $userId
        );

        if (!$check->execute()) {
            $check->close();

            response(
                false,
                "Failed to verify turf ownership",
                [],
                500
            );
        }

        $result = $check->get_result();

        if ($result->num_rows === 0) {
            $check->close();

            response(
                false,
                "You can delete only your own turf",
                [],
                403
            );
        }

        $check->close();
    }

    // -------------------------
    // Check booking history
    // -------------------------
    $bookingCheck = $con->prepare(
        "SELECT COUNT(*) AS total
         FROM bookings
         WHERE turf_id = ?"
    );

    if (!$bookingCheck) {
        response(
            false,
            "Could not check turf bookings. Verify that bookings.turf_id exists.",
            [],
            500
        );
    }

    $bookingCheck->bind_param(
        "i",
        $turfId
    );

    if (!$bookingCheck->execute()) {
        $bookingCheck->close();

        response(
            false,
            "Failed to check turf booking history",
            [],
            500
        );
    }

    $bookingResult =
        $bookingCheck
            ->get_result()
            ->fetch_assoc();

    $bookingCount = (int) (
        $bookingResult["total"] ?? 0
    );

    $bookingCheck->close();

    // -------------------------
    // Soft delete
    // -------------------------
    if ($bookingCount > 0) {

        $stmt = $con->prepare(
            "UPDATE turf_tb
             SET status = 'deleted'
             WHERE turf_id = ?"
        );

        if (!$stmt) {
            response(
                false,
                "Failed to prepare turf delete",
                [],
                500
            );
        }

        $stmt->bind_param(
            "i",
            $turfId
        );

        if (!$stmt->execute()) {
            $stmt->close();

            response(
                false,
                "Failed to mark turf as deleted",
                [],
                500
            );
        }

        $stmt->close();

        response(
            true,
            "Turf marked as deleted because booking history exists"
        );
    }

    // -------------------------
    // Hard delete
    // -------------------------
    $stmt = $con->prepare(
        "DELETE FROM turf_tb
         WHERE turf_id = ?"
    );

    if (!$stmt) {
        response(
            false,
            "Failed to prepare turf delete",
            [],
            500
        );
    }

    $stmt->bind_param(
        "i",
        $turfId
    );

    if (!$stmt->execute()) {
        $error = $stmt->error;
        $stmt->close();

        response(
            false,
            "Failed to delete turf: " . $error,
            [],
            500
        );
    }

    $stmt->close();

    response(
        true,
        "Turf deleted successfully"
    );
}

// =========================
// UNSUPPORTED METHOD
// =========================
response(
    false,
    "Unsupported request method",
    [],
    405
);

?>