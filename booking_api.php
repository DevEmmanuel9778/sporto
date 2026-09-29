<?php

// ============================================================
// SPORTO - BOOKING API
//
// GET    -> User / Owner / Admin
// POST   -> User creates booking
// PUT    -> Owner / Admin updates booking status
// PATCH  -> Owner / Admin updates booking status
// DELETE -> User cancels own booking
// ============================================================

header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Max-Age: 86400");

// ============================================================
// OPTIONS
// ============================================================

if (
    ($_SERVER["REQUEST_METHOD"] ?? "") === "OPTIONS"
) {
    http_response_code(204);
    exit;
}

// ============================================================
// IMPORTANT:
// booking_api.php is in /var/www/html/
// connection.php is in /var/www/html/
// config/jwt.php is in /var/www/html/config/
// ============================================================

require_once __DIR__ . "/connection.php";
require_once __DIR__ . "/config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// ============================================================
// RESPONSE HELPER
// ============================================================

function response(
    bool $status,
    string $message,
    $data = null,
    int $code = 200
): never {

    http_response_code($code);

    $output = [
        "status" => $status,
        "message" => $message,
    ];

    if ($data !== null) {
        $output["data"] = $data;
    }

    echo json_encode(
        $output,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

// ============================================================
// BEARER TOKEN
// ============================================================

function getBearerToken(): ?string
{
    $authorization = null;

    // Apache / Render
    if (function_exists("getallheaders")) {

        $headers = getallheaders();

        foreach ($headers as $key => $value) {

            if (
                strtolower((string) $key)
                === "authorization"
            ) {
                $authorization =
                    (string) $value;

                break;
            }
        }
    }

    // Fallback
    if (!$authorization) {

        $authorization =
            $_SERVER["HTTP_AUTHORIZATION"]
            ?? $_SERVER["REDIRECT_HTTP_AUTHORIZATION"]
            ?? null;
    }

    if (
        !$authorization ||
        !preg_match(
            "/^Bearer\s+(.+)$/i",
            trim($authorization),
            $matches
        )
    ) {
        return null;
    }

    return trim($matches[1]);
}

// ============================================================
// AUTH
// ============================================================

function authenticate(
    array $roles = [
        "user",
        "owner",
        "admin",
    ]
): array {

    global $secret_key;

    $token =
        getBearerToken();

    if (!$token) {

        response(
            false,
            "Authorization token is required",
            null,
            401
        );
    }

    try {

        $decoded =
            JWT::decode(
                $token,
                new Key(
                    $secret_key,
                    "HS256"
                )
            );

        $payload =
            (array) $decoded;

        if (
            ($payload["type"] ?? "")
            !== "access"
        ) {

            response(
                false,
                "Invalid access token",
                null,
                401
            );
        }

        $role =
            strtolower(
                (string) (
                    $payload["role"] ?? ""
                )
            );

        if (
            !in_array(
                $role,
                $roles,
                true
            )
        ) {

            response(
                false,
                "Access denied",
                null,
                403
            );
        }

        $payload["role"] =
            $role;

        return $payload;

    } catch (Throwable $e) {

        response(
            false,
            "Invalid or expired token",
            null,
            401
        );
    }
}

// ============================================================
// DATABASE
// ============================================================

if (
    !isset($con) ||
    !($con instanceof mysqli)
) {

    response(
        false,
        "Database connection failed",
        null,
        500
    );
}

if (
    $con->connect_errno
) {

    response(
        false,
        "Database connection failed",
        null,
        500
    );
}

$con->set_charset("utf8mb4");

// ============================================================
// INPUT
// ============================================================

$method =
    strtoupper(
        $_SERVER["REQUEST_METHOD"]
        ?? ""
    );

$raw =
    file_get_contents(
        "php://input"
    );

$data =
    json_decode(
        $raw ?: "",
        true
    );

if (!is_array($data)) {
    $data = [];
}

// ============================================================
// AUTHENTICATE
// ============================================================

$user =
    authenticate();

$role =
    strtolower(
        (string) (
            $user["role"] ?? ""
        )
    );

$userId =
    (int) (
        $user["user_id"]
        ?? $user["id"]
        ?? 0
    );

if ($userId <= 0) {

    response(
        false,
        "Invalid user ID in token",
        null,
        401
    );
}

// ============================================================
// POST
// USER CREATE BOOKING
// ============================================================

if ($method === "POST") {

    if ($role !== "user") {

        response(
            false,
            "Only users can create bookings",
            null,
            403
        );
    }

    $turfId =
        (int) (
            $data["turf_id"]
            ?? 0
        );

    $slotId =
        (int) (
            $data["slot_id"]
            ?? 0
        );

    $bookingDate =
        trim(
            (string) (
                $data["booking_date"]
                ?? ""
            )
        );

    // Client may send amount,
    // but server will NOT trust it.
    $clientAmount =
        isset($data["amount"])
            ? (float) $data["amount"]
            : null;

    if (
        $turfId <= 0 ||
        $slotId <= 0 ||
        $bookingDate === ""
    ) {

        response(
            false,
            "turf_id, slot_id and booking_date are required",
            null,
            422
        );
    }

    // ========================================================
    // DATE VALIDATION
    // ========================================================

    $dateObject =
        DateTime::createFromFormat(
            "Y-m-d",
            $bookingDate
        );

    if (
        !$dateObject ||
        $dateObject->format("Y-m-d")
        !== $bookingDate
    ) {

        response(
            false,
            "Invalid booking date. Use YYYY-MM-DD",
            null,
            422
        );
    }

    // ========================================================
    // TRANSACTION
    // ========================================================

    $con->begin_transaction();

    try {

        // ====================================================
        // CHECK TURF
        // ====================================================

        $turfStmt =
            $con->prepare(
                "
                SELECT
                    turf_id,
                    turf_name,
                    status
                FROM turf_tb
                WHERE turf_id = ?
                LIMIT 1
                FOR UPDATE
                "
            );

        if (!$turfStmt) {
            throw new Exception(
                $con->error
            );
        }

        $turfStmt->bind_param(
            "i",
            $turfId
        );

        if (
            !$turfStmt->execute()
        ) {

            throw new Exception(
                $turfStmt->error
            );
        }

        $turfResult =
            $turfStmt->get_result();

        if (
            $turfResult->num_rows === 0
        ) {

            $turfStmt->close();

            throw new Exception(
                "Turf not found"
            );
        }

        $turf =
            $turfResult
                ->fetch_assoc();

        $turfStmt->close();

        if (
            strtolower(
                (string) (
                    $turf["status"] ?? ""
                )
            )
            !== "active"
        ) {

            throw new Exception(
                "This turf is not available for booking"
            );
        }

        // ====================================================
        // CHECK SLOT
        // ====================================================

        $slotStmt =
            $con->prepare(
                "
                SELECT
                    slot_id,
                    turf_id,
                    date,
                    start_time,
                    end_time,
                    price,
                    status
                FROM turf_slots
                WHERE slot_id = ?
                  AND turf_id = ?
                LIMIT 1
                FOR UPDATE
                "
            );

        if (!$slotStmt) {

            throw new Exception(
                $con->error
            );
        }

        $slotStmt->bind_param(
            "ii",
            $slotId,
            $turfId
        );

        if (
            !$slotStmt->execute()
        ) {

            throw new Exception(
                $slotStmt->error
            );
        }

        $slotResult =
            $slotStmt->get_result();

        if (
            $slotResult->num_rows === 0
        ) {

            $slotStmt->close();

            throw new Exception(
                "Selected slot not found"
            );
        }

        $slot =
            $slotResult
                ->fetch_assoc();

        $slotStmt->close();

        // ====================================================
        // DATE MUST MATCH SLOT
        // ====================================================

        if (
            (string) $slot["date"]
            !== $bookingDate
        ) {

            throw new Exception(
                "Selected slot is not available for this date"
            );
        }

        // ====================================================
        // SLOT STATUS
        // ====================================================

        $slotStatus =
            strtolower(
                (string) (
                    $slot["status"]
                    ?? ""
                )
            );

        if (
            in_array(
                $slotStatus,
                [
                    "booked",
                    "unavailable",
                    "inactive",
                ],
                true
            )
        ) {

            throw new Exception(
                "Selected slot is already unavailable"
            );
        }

        if (
            $slotStatus !== "available"
        ) {

            throw new Exception(
                "Selected slot is not available"
            );
        }

        // ====================================================
        // ACTIVE BOOKING CHECK
        // ====================================================

        $bookingCheck =
            $con->prepare(
                "
                SELECT
                    booking_id
                FROM bookings
                WHERE turf_id = ?
                  AND slot_id = ?
                  AND booking_date = ?
                  AND status IN
                  (
                      'pending',
                      'confirmed',
                      'paid'
                  )
                LIMIT 1
                FOR UPDATE
                "
            );

        if (!$bookingCheck) {

            throw new Exception(
                $con->error
            );
        }

        $bookingCheck->bind_param(
            "iis",
            $turfId,
            $slotId,
            $bookingDate
        );

        if (
            !$bookingCheck->execute()
        ) {

            throw new Exception(
                $bookingCheck->error
            );
        }

        $existingBooking =
            $bookingCheck
                ->get_result();

        if (
            $existingBooking->num_rows > 0
        ) {

            $bookingCheck->close();

            throw new Exception(
                "This slot is already booked"
            );
        }

        $bookingCheck->close();

        // ====================================================
        // SERVER AUTHORITATIVE AMOUNT
        // ====================================================

        $amount =
            (float) (
                $slot["price"]
                ?? 0
            );

        if ($amount <= 0) {

            throw new Exception(
                "Selected slot has an invalid price"
            );
        }

        // ====================================================
        // CREATE BOOKING
        // ====================================================

        $bookingStatus =
            "pending";

        $insert =
            $con->prepare(
                "
                INSERT INTO bookings
                (
                    user_id,
                    turf_id,
                    slot_id,
                    booking_date,
                    amount,
                    status
                )
                VALUES
                (
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?
                )
                "
            );

        if (!$insert) {

            throw new Exception(
                $con->error
            );
        }

        $insert->bind_param(
            "iiisds",
            $userId,
            $turfId,
            $slotId,
            $bookingDate,
            $amount,
            $bookingStatus
        );

        if (
            !$insert->execute()
        ) {

            $error =
                $insert->error;

            $insert->close();

            throw new Exception(
                $error
            );
        }

        $bookingId =
            (int) $insert->insert_id;

        $insert->close();

        // ====================================================
        // LOCK SLOT AS BOOKED
        // ====================================================

        $slotUpdate =
            $con->prepare(
                "
                UPDATE turf_slots
                SET status = 'booked'
                WHERE slot_id = ?
                "
            );

        if (!$slotUpdate) {

            throw new Exception(
                $con->error
            );
        }

        $slotUpdate->bind_param(
            "i",
            $slotId
        );

        if (
            !$slotUpdate->execute()
        ) {

            throw new Exception(
                $slotUpdate->error
            );
        }

        $slotUpdate->close();

        // ====================================================
        // COMMIT
        // ====================================================

        $con->commit();

        // ====================================================
        // RESPONSE DATA
        // Compatible with both old and new Flutter clients
        // ====================================================

        $booking = [
            "booking_id" =>
                $bookingId,

            "user_id" =>
                $userId,

            "turf_id" =>
                $turfId,

            "slot_id" =>
                $slotId,

            "booking_date" =>
                $bookingDate,

            "amount" =>
                $amount,

            "status" =>
                $bookingStatus,

            "turf_name" =>
                (string) (
                    $turf["turf_name"]
                    ?? ""
                ),

            "start_time" =>
                (string) (
                    $slot["start_time"]
                    ?? ""
                ),

            "end_time" =>
                (string) (
                    $slot["end_time"]
                    ?? ""
                ),
        ];

        /*
         * "message" is intentionally "success"
         * because the older Flutter BookingApiService
         * checks for exactly this value.
         */
        http_response_code(201);

        echo json_encode(
            [
                "status" => true,
                "success" => true,
                "message" => "success",

                "booking" =>
                    $booking,

                "data" =>
                    $booking,

                "booking_id" =>
                    $bookingId,
            ],
            JSON_UNESCAPED_UNICODE |
            JSON_UNESCAPED_SLASHES
        );

        exit;

    } catch (Throwable $e) {

        $con->rollback();

        response(
            false,
            $e->getMessage(),
            null,
            409
        );
    }
}

// ============================================================
// GET BOOKINGS
// ============================================================

if ($method === "GET") {

    if ($role === "user") {

        $stmt =
            $con->prepare(
                "
                SELECT
                    b.*,
                    t.turf_name,
                    t.location,
                    ts.start_time,
                    ts.end_time
                FROM bookings b

                INNER JOIN turf_tb t
                    ON t.turf_id = b.turf_id

                INNER JOIN turf_slots ts
                    ON ts.slot_id = b.slot_id

                WHERE b.user_id = ?

                ORDER BY
                    b.booking_date DESC,
                    ts.start_time DESC
                "
            );

        if (!$stmt) {

            response(
                false,
                "Failed to prepare booking list",
                null,
                500
            );
        }

        $stmt->bind_param(
            "i",
            $userId
        );

    } elseif ($role === "owner") {

        $stmt =
            $con->prepare(
                "
                SELECT
                    b.*,
                    t.turf_name,
                    t.location,
                    ts.start_time,
                    ts.end_time
                FROM bookings b

                INNER JOIN turf_tb t
                    ON t.turf_id = b.turf_id

                INNER JOIN turf_slots ts
                    ON ts.slot_id = b.slot_id

                WHERE t.owner_id = ?

                ORDER BY
                    b.booking_date DESC,
                    ts.start_time DESC
                "
            );

        if (!$stmt) {

            response(
                false,
                "Failed to prepare booking list",
                null,
                500
            );
        }

        $stmt->bind_param(
            "i",
            $userId
        );

    } else {

        $stmt =
            $con->prepare(
                "
                SELECT
                    b.*,
                    t.turf_name,
                    t.location,
                    ts.start_time,
                    ts.end_time
                FROM bookings b

                INNER JOIN turf_tb t
                    ON t.turf_id = b.turf_id

                INNER JOIN turf_slots ts
                    ON ts.slot_id = b.slot_id

                ORDER BY
                    b.booking_date DESC,
                    ts.start_time DESC
                "
            );

        if (!$stmt) {

            response(
                false,
                "Failed to prepare booking list",
                null,
                500
            );
        }
    }

    if (!$stmt->execute()) {

        $error =
            $stmt->error;

        $stmt->close();

        response(
            false,
            "Failed to fetch bookings",
            null,
            500
        );
    }

    $result =
        $stmt->get_result();

    $bookings = [];

    while (
        $row =
            $result->fetch_assoc()
    ) {

        $bookings[] =
            $row;
    }

    $stmt->close();

    // Compatible response
    http_response_code(200);

    echo json_encode(
        [
            "status" => true,
            "success" => true,
            "message" => "success",
            "bookings" => $bookings,
            "data" => $bookings,
        ],
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

// ============================================================
// PUT / PATCH
// OWNER / ADMIN UPDATE BOOKING STATUS
// ============================================================

if (
    $method === "PUT" ||
    $method === "PATCH"
) {

    if (
        !in_array(
            $role,
            [
                "owner",
                "admin",
            ],
            true
        )
    ) {

        response(
            false,
            "Only owner or admin can update bookings",
            null,
            403
        );
    }

    $bookingId =
        (int) (
            $data["booking_id"]
            ?? 0
        );

    $newStatus =
        strtolower(
            trim(
                (string) (
                    $data["status"]
                    ?? ""
                )
            )
        );

    $allowedStatuses = [
        "pending",
        "confirmed",
        "paid",
        "cancelled",
        "completed",
    ];

    if (
        $bookingId <= 0 ||
        !in_array(
            $newStatus,
            $allowedStatuses,
            true
        )
    ) {

        response(
            false,
            "Valid booking_id and status are required",
            null,
            422
        );
    }

    // ========================================================
    // OWNER
    // ========================================================

    if (
        $role === "owner"
    ) {

        $stmt =
            $con->prepare(
                "
                UPDATE bookings b

                INNER JOIN turf_tb t
                    ON t.turf_id = b.turf_id

                SET
                    b.status = ?

                WHERE
                    b.booking_id = ?
                    AND t.owner_id = ?
                "
            );

        if (!$stmt) {

            response(
                false,
                "Failed to prepare booking update",
                null,
                500
            );
        }

        $stmt->bind_param(
            "sii",
            $newStatus,
            $bookingId,
            $userId
        );

    } else {

        // ====================================================
        // ADMIN
        // ====================================================

        $stmt =
            $con->prepare(
                "
                UPDATE bookings
                SET status = ?
                WHERE booking_id = ?
                "
            );

        if (!$stmt) {

            response(
                false,
                "Failed to prepare booking update",
                null,
                500
            );
        }

        $stmt->bind_param(
            "si",
            $newStatus,
            $bookingId
        );
    }

    if (
        !$stmt->execute()
    ) {

        $error =
            $stmt->error;

        $stmt->close();

        response(
            false,
            "Failed to update booking",
            null,
            500
        );
    }

    if (
        $stmt->affected_rows === 0
    ) {

        $stmt->close();

        response(
            false,
            "Booking not found or access denied",
            null,
            404
        );
    }

    $stmt->close();

    // ========================================================
    // RELEASE SLOT WHEN CANCELLED
    // ========================================================

    if (
        $newStatus === "cancelled"
    ) {

        $slot =
            $con->prepare(
                "
                UPDATE turf_slots ts

                INNER JOIN bookings b
                    ON b.slot_id = ts.slot_id

                SET
                    ts.status = 'available'

                WHERE
                    b.booking_id = ?
                "
            );

        if ($slot) {

            $slot->bind_param(
                "i",
                $bookingId
            );

            $slot->execute();

            $slot->close();
        }
    }

    response(
        true,
        "Booking status updated successfully",
        [
            "booking_id" =>
                $bookingId,

            "status" =>
                $newStatus,
        ]
    );
}

// ============================================================
// DELETE
// USER CANCEL OWN BOOKING
// ============================================================

if (
    $method === "DELETE"
) {

    if (
        $role !== "user"
    ) {

        response(
            false,
            "Only users can cancel their own bookings",
            null,
            403
        );
    }

    $bookingId =
        (int) (
            $data["booking_id"]
            ?? $_GET["booking_id"]
            ?? 0
        );

    if (
        $bookingId <= 0
    ) {

        response(
            false,
            "booking_id is required",
            null,
            422
        );
    }

    $con->begin_transaction();

    try {

        // ====================================================
        // FIND BOOKING
        // ====================================================

        $stmt =
            $con->prepare(
                "
                SELECT
                    booking_id,
                    slot_id,
                    status
                FROM bookings
                WHERE
                    booking_id = ?
                    AND user_id = ?
                LIMIT 1
                FOR UPDATE
                "
            );

        if (!$stmt) {

            throw new Exception(
                $con->error
            );
        }

        $stmt->bind_param(
            "ii",
            $bookingId,
            $userId
        );

        if (
            !$stmt->execute()
        ) {

            throw new Exception(
                $stmt->error
            );
        }

        $result =
            $stmt->get_result();

        if (
            $result->num_rows === 0
        ) {

            $stmt->close();

            throw new Exception(
                "Booking not found"
            );
        }

        $booking =
            $result
                ->fetch_assoc();

        $stmt->close();

        // ====================================================
        // CHECK STATUS
        // ====================================================

        if (
            !in_array(
                strtolower(
                    (string)
                        $booking["status"]
                ),
                [
                    "pending",
                    "confirmed",
                ],
                true
            )
        ) {

            throw new Exception(
                "This booking cannot be cancelled"
            );
        }

        // ====================================================
        // CANCEL BOOKING
        // ====================================================

        $update =
            $con->prepare(
                "
                UPDATE bookings
                SET status = 'cancelled'
                WHERE
                    booking_id = ?
                    AND user_id = ?
                "
            );

        if (!$update) {

            throw new Exception(
                $con->error
            );
        }

        $update->bind_param(
            "ii",
            $bookingId,
            $userId
        );

        if (
            !$update->execute()
        ) {

            throw new Exception(
                $update->error
            );
        }

        $update->close();

        // ====================================================
        // RELEASE SLOT
        // ====================================================

        $slotId =
            (int) (
                $booking["slot_id"]
                ?? 0
            );

        $slotUpdate =
            $con->prepare(
                "
                UPDATE turf_slots
                SET status = 'available'
                WHERE slot_id = ?
                "
            );

        if (!$slotUpdate) {

            throw new Exception(
                $con->error
            );
        }

        $slotUpdate->bind_param(
            "i",
            $slotId
        );

        if (
            !$slotUpdate->execute()
        ) {

            throw new Exception(
                $slotUpdate->error
            );
        }

        $slotUpdate->close();

        $con->commit();

        response(
            true,
            "Booking cancelled successfully",
            [
                "booking_id" =>
                    $bookingId,
            ]
        );

    } catch (Throwable $e) {

        $con->rollback();

        response(
            false,
            $e->getMessage(),
            null,
            409
        );
    }
}

// ============================================================
// UNSUPPORTED
// ============================================================

response(
    false,
    "Unsupported request method",
    null,
    405
);

?>