<?php

// ============================================================
// ERROR HANDLING
// ============================================================

ini_set("display_errors", "0");
ini_set("log_errors", "1");
error_reporting(E_ALL);

ob_start();

// ============================================================
// HEADERS
// ============================================================

header("Content-Type: application/json; charset=UTF-8");
header("Cache-Control: no-store");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Max-Age: 86400");

// ============================================================
// OPTIONS
// ============================================================

if (($_SERVER["REQUEST_METHOD"] ?? "") === "OPTIONS") {
    http_response_code(204);
    exit;
}

// ============================================================
// REQUIRED FILES
// ============================================================

require_once __DIR__ . "/connection.php";
require_once __DIR__ . "/config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// ============================================================
// RESPONSE
// ============================================================

function response(
    bool $status,
    string $message,
    $data = null,
    int $code = 200
): void {
    if (ob_get_level() > 0) {
        ob_clean();
    }

    http_response_code($code);

    $out = [
        "status" => $status,
        "message" => $message,
    ];

    if ($data !== null) {
        $out["data"] = $data;
    }

    echo json_encode(
        $out,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

// ============================================================
// GET BEARER TOKEN
// ============================================================

function getBearerToken(): ?string
{
    $authorization = null;

    if (function_exists("getallheaders")) {
        $headers = getallheaders();

        foreach ($headers as $key => $value) {
            if (strtolower((string)$key) === "authorization") {
                $authorization = (string)$value;
                break;
            }
        }
    }

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
// AUTHENTICATION
// ============================================================

function auth(
    array $allowedRoles = ["user", "owner", "admin"]
): array {
    global $secret_key;

    $token = getBearerToken();

    if (!$token) {
        response(
            false,
            "Authorization token is required",
            null,
            401
        );
    }

    try {
        $payload = (array)JWT::decode(
            $token,
            new Key($secret_key, "HS256")
        );

        if (($payload["type"] ?? "") !== "access") {
            response(
                false,
                "Invalid access token",
                null,
                401
            );
        }

        $role = (string)($payload["role"] ?? "");

        if (!in_array($role, $allowedRoles, true)) {
            response(
                false,
                "Access denied",
                null,
                403
            );
        }

        return $payload;
    } catch (Throwable $e) {
        response(
            false,
            "Invalid or expired token",
            null,
            401
        );
    }

    return [];
}

// ============================================================
// DATABASE CHECK
// ============================================================

if (
    !isset($con) ||
    !($con instanceof mysqli) ||
    $con->connect_error
) {
    response(
        false,
        "Database connection failed",
        null,
        500
    );
}

// ============================================================
// REQUEST DATA
// ============================================================

$method = strtoupper(
    $_SERVER["REQUEST_METHOD"] ?? ""
);

$user = auth();

$role = (string)(
    $user["role"] ??
    ""
);

$userId = (int)(
    $user["user_id"] ??
    $user["id"] ??
    0
);

$rawBody = file_get_contents("php://input");

$data = [];

if ($rawBody !== false && trim($rawBody) !== "") {
    $decodedBody = json_decode(
        $rawBody,
        true
    );

    if (is_array($decodedBody)) {
        $data = $decodedBody;
    }
}

// ============================================================
// INTERNAL TRANSACTION REFERENCE
// ============================================================

function generateTransactionId(): string
{
    try {
        return "SPT-" .
            date("YmdHis") .
            "-" .
            strtoupper(
                bin2hex(
                    random_bytes(5)
                )
            );
    } catch (Throwable $e) {
        return "SPT-" .
            date("YmdHis") .
            "-" .
            strtoupper(
                substr(
                    md5(
                        uniqid(
                            "",
                            true
                        )
                    ),
                    0,
                    10
                )
            );
    }
}

// ============================================================
// POST - CREATE PAYMENT SESSION
// ============================================================

if ($method === "POST") {

    if ($role !== "user") {
        response(
            false,
            "Only users can make payments",
            null,
            403
        );
    }

    $paymentType = strtolower(
        trim(
            (string)(
                $data["payment_type"] ??
                ""
            )
        )
    );

    $paymentMethod = trim(
        (string)(
            $data["payment_method"] ??
            ""
        )
    );

    if (
        !in_array(
            $paymentType,
            ["turf", "product"],
            true
        )
    ) {
        response(
            false,
            "payment_type must be turf or product",
            null,
            422
        );
    }

    if ($paymentMethod === "") {
        response(
            false,
            "payment_method is required",
            null,
            422
        );
    }

    $con->begin_transaction();

    try {

        // ========================================================
        // TURF PAYMENT
        // ========================================================

        if ($paymentType === "turf") {

            $bookingId = (int)(
                $data["booking_id"] ??
                0
            );

            if ($bookingId <= 0) {
                throw new Exception(
                    "booking_id is required"
                );
            }

            $stmt = $con->prepare(
                "SELECT
                    b.booking_id,
                    b.user_id,
                    b.turf_id,
                    b.slot_id,
                    b.booking_date,
                    b.amount,
                    b.status,
                    t.turf_name,
                    t.location,
                    ts.start_time,
                    ts.end_time
                 FROM bookings b
                 INNER JOIN turf_tb t
                    ON t.turf_id = b.turf_id
                 INNER JOIN turf_slots ts
                    ON ts.slot_id = b.slot_id
                 WHERE b.booking_id = ?
                   AND b.user_id = ?
                 LIMIT 1
                 FOR UPDATE"
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

            if (!$stmt->execute()) {
                throw new Exception(
                    $stmt->error
                );
            }

            $result = $stmt->get_result();

            if ($result->num_rows === 0) {
                $stmt->close();

                throw new Exception(
                    "Booking not found"
                );
            }

            $booking = $result->fetch_assoc();

            $stmt->close();

            $bookingStatus = strtolower(
                trim(
                    (string)$booking["status"]
                )
            );

            if (
                in_array(
                    $bookingStatus,
                    [
                        "paid",
                        "completed",
                    ],
                    true
                )
            ) {
                throw new Exception(
                    "Booking is already paid"
                );
            }

            // ----------------------------------------------------
            // CHECK EXISTING PENDING PAYMENT
            // ----------------------------------------------------

            $existing = $con->prepare(
                "SELECT
                    payment_id,
                    transaction_id,
                    amount,
                    payment_method,
                    status,
                    payment_date
                 FROM payments
                 WHERE booking_id = ?
                   AND payment_type = 'turf'
                   AND status = 'pending'
                 ORDER BY payment_id DESC
                 LIMIT 1"
            );

            if (!$existing) {
                throw new Exception(
                    $con->error
                );
            }

            $existing->bind_param(
                "i",
                $bookingId
            );

            if (!$existing->execute()) {
                throw new Exception(
                    $existing->error
                );
            }

            $existingResult =
                $existing->get_result();

            if ($existingResult->num_rows > 0) {

                $existingPayment =
                    $existingResult->fetch_assoc();

                $existing->close();

                $con->commit();

                response(
                    true,
                    "Pending turf payment already exists",
                    [
                        "payment_id" =>
                            (int)$existingPayment["payment_id"],

                        "payment_type" =>
                            "turf",

                        "booking_id" =>
                            $bookingId,

                        "amount" =>
                            (float)$existingPayment["amount"],

                        "payment_method" =>
                            $existingPayment["payment_method"],

                        "transaction_id" =>
                            $existingPayment["transaction_id"],

                        "status" =>
                            "pending",

                        "turf_name" =>
                            $booking["turf_name"],

                        "location" =>
                            $booking["location"],

                        "booking_date" =>
                            $booking["booking_date"],

                        "start_time" =>
                            $booking["start_time"],

                        "end_time" =>
                            $booking["end_time"],
                    ],
                    200
                );
            }

            $existing->close();

            // ----------------------------------------------------
            // CREATE NEW PENDING PAYMENT
            // ----------------------------------------------------

            $amount = (float)$booking["amount"];

            $transactionId =
                generateTransactionId();

            $status = "pending";

            $insert = $con->prepare(
                "INSERT INTO payments
                (
                    booking_id,
                    order_id,
                    payment_type,
                    amount,
                    payment_method,
                    transaction_id,
                    status,
                    payment_date
                )
                VALUES
                (
                    ?,
                    NULL,
                    'turf',
                    ?,
                    ?,
                    ?,
                    ?,
                    CURDATE()
                )"
            );

            if (!$insert) {
                throw new Exception(
                    $con->error
                );
            }

            $insert->bind_param(
                "idsss",
                $bookingId,
                $amount,
                $paymentMethod,
                $transactionId,
                $status
            );

            if (!$insert->execute()) {
                throw new Exception(
                    $insert->error
                );
            }

            $paymentId =
                (int)$insert->insert_id;

            $insert->close();

            $con->commit();

            response(
                true,
                "Turf payment session created",
                [
                    "payment_id" =>
                        $paymentId,

                    "payment_type" =>
                        "turf",

                    "booking_id" =>
                        $bookingId,

                    "amount" =>
                        $amount,

                    "payment_method" =>
                        $paymentMethod,

                    "transaction_id" =>
                        $transactionId,

                    "status" =>
                        "pending",

                    "turf_id" =>
                        (int)$booking["turf_id"],

                    "slot_id" =>
                        (int)$booking["slot_id"],

                    "turf_name" =>
                        $booking["turf_name"],

                    "location" =>
                        $booking["location"],

                    "booking_date" =>
                        $booking["booking_date"],

                    "start_time" =>
                        $booking["start_time"],

                    "end_time" =>
                        $booking["end_time"],
                ],
                201
            );
        }

        // ========================================================
        // PRODUCT PAYMENT
        // ========================================================

        $orderId = (int)(
            $data["order_id"] ??
            0
        );

        if ($orderId <= 0) {
            throw new Exception(
                "order_id is required"
            );
        }

        $stmt = $con->prepare(
            "SELECT
                order_id,
                user_id,
                amount,
                status
             FROM orders
             WHERE order_id = ?
               AND user_id = ?
             LIMIT 1
             FOR UPDATE"
        );

        if (!$stmt) {
            throw new Exception(
                $con->error
            );
        }

        $stmt->bind_param(
            "ii",
            $orderId,
            $userId
        );

        if (!$stmt->execute()) {
            throw new Exception(
                $stmt->error
            );
        }

        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            $stmt->close();

            throw new Exception(
                "Order not found"
            );
        }

        $order = $result->fetch_assoc();

        $stmt->close();

        $orderStatus = strtolower(
            trim(
                (string)$order["status"]
            )
        );

        if (
            in_array(
                $orderStatus,
                [
                    "paid",
                    "delivered",
                ],
                true
            )
        ) {
            throw new Exception(
                "Order is already paid"
            );
        }

        // --------------------------------------------------------
        // EXISTING PENDING PRODUCT PAYMENT
        // --------------------------------------------------------

        $existing = $con->prepare(
            "SELECT
                payment_id,
                transaction_id,
                amount,
                payment_method,
                status,
                payment_date
             FROM payments
             WHERE order_id = ?
               AND payment_type = 'product'
               AND status = 'pending'
             ORDER BY payment_id DESC
             LIMIT 1"
        );

        if (!$existing) {
            throw new Exception(
                $con->error
            );
        }

        $existing->bind_param(
            "i",
            $orderId
        );

        if (!$existing->execute()) {
            throw new Exception(
                $existing->error
            );
        }

        $existingResult =
            $existing->get_result();

        if ($existingResult->num_rows > 0) {

            $existingPayment =
                $existingResult->fetch_assoc();

            $existing->close();

            $con->commit();

            response(
                true,
                "Pending product payment already exists",
                [
                    "payment_id" =>
                        (int)$existingPayment["payment_id"],

                    "payment_type" =>
                        "product",

                    "order_id" =>
                        $orderId,

                    "amount" =>
                        (float)$existingPayment["amount"],

                    "payment_method" =>
                        $existingPayment["payment_method"],

                    "transaction_id" =>
                        $existingPayment["transaction_id"],

                    "status" =>
                        "pending",
                ],
                200
            );
        }

        $existing->close();

        // --------------------------------------------------------
        // CREATE PRODUCT PAYMENT SESSION
        // --------------------------------------------------------

        $amount = (float)$order["amount"];

        $transactionId =
            generateTransactionId();

        $status = "pending";

        $insert = $con->prepare(
            "INSERT INTO payments
            (
                booking_id,
                order_id,
                payment_type,
                amount,
                payment_method,
                transaction_id,
                status,
                payment_date
            )
            VALUES
            (
                NULL,
                ?,
                'product',
                ?,
                ?,
                ?,
                ?,
                CURDATE()
            )"
        );

        if (!$insert) {
            throw new Exception(
                $con->error
            );
        }

        $insert->bind_param(
            "idsss",
            $orderId,
            $amount,
            $paymentMethod,
            $transactionId,
            $status
        );

        if (!$insert->execute()) {
            throw new Exception(
                $insert->error
            );
        }

        $paymentId =
            (int)$insert->insert_id;

        $insert->close();

        $con->commit();

        response(
            true,
            "Product payment session created",
            [
                "payment_id" =>
                    $paymentId,

                "payment_type" =>
                    "product",

                "order_id" =>
                    $orderId,

                "amount" =>
                    $amount,

                "payment_method" =>
                    $paymentMethod,

                "transaction_id" =>
                    $transactionId,

                "status" =>
                    "pending",
            ],
            201
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
// GET - PAYMENT STATUS / PAYMENT DETAILS
// ============================================================

if ($method === "GET") {

    $requestedBookingId = (int)(
        $_GET["booking_id"] ??
        0
    );

    $requestedPaymentId = (int)(
        $_GET["payment_id"] ??
        0
    );

    // ========================================================
    // USER
    // ========================================================

    if ($role === "user") {

        // ------------------------------------------------------
        // SPECIFIC BOOKING
        // ------------------------------------------------------

        if ($requestedBookingId > 0) {

            $stmt = $con->prepare(
                "SELECT
                    p.payment_id,
                    p.booking_id,
                    p.order_id,
                    p.payment_type,
                    p.amount,
                    p.payment_method,
                    p.transaction_id,
                    p.status,
                    p.payment_date,

                    b.turf_id,
                    b.slot_id,
                    b.booking_date,
                    b.status AS booking_status,

                    t.turf_name,
                    t.location,

                    ts.start_time,
                    ts.end_time

                 FROM payments p

                 INNER JOIN bookings b
                    ON b.booking_id = p.booking_id

                 INNER JOIN turf_tb t
                    ON t.turf_id = b.turf_id

                 INNER JOIN turf_slots ts
                    ON ts.slot_id = b.slot_id

                 WHERE p.payment_type = 'turf'
                   AND p.booking_id = ?
                   AND b.user_id = ?

                 ORDER BY p.payment_id DESC
                 LIMIT 1"
            );

            if (!$stmt) {
                response(
                    false,
                    "Failed to prepare payment query",
                    null,
                    500
                );
            }

            $stmt->bind_param(
                "ii",
                $requestedBookingId,
                $userId
            );

            if (!$stmt->execute()) {
                $message = $stmt->error;
                $stmt->close();

                response(
                    false,
                    $message,
                    null,
                    500
                );
            }

            $result = $stmt->get_result();

            if ($result->num_rows === 0) {
                $stmt->close();

                response(
                    true,
                    "No payment found for this booking",
                    [],
                    200
                );
            }

            $payment =
                $result->fetch_assoc();

            $stmt->close();

            response(
                true,
                "Payment fetched successfully",
                [
                    $payment,
                ],
                200
            );
        }

        // ------------------------------------------------------
        // SPECIFIC PAYMENT
        // ------------------------------------------------------

        if ($requestedPaymentId > 0) {

            $stmt = $con->prepare(
                "SELECT
                    p.*,

                    b.user_id,
                    b.turf_id,
                    b.slot_id,
                    b.booking_date,
                    b.status AS booking_status,

                    t.turf_name,
                    t.location,

                    ts.start_time,
                    ts.end_time

                 FROM payments p

                 LEFT JOIN bookings b
                    ON b.booking_id = p.booking_id

                 LEFT JOIN turf_tb t
                    ON t.turf_id = b.turf_id

                 LEFT JOIN turf_slots ts
                    ON ts.slot_id = b.slot_id

                 WHERE p.payment_id = ?

                   AND (
                        (
                            p.payment_type = 'turf'
                            AND b.user_id = ?
                        )
                        OR
                        (
                            p.payment_type = 'product'
                            AND p.order_id IN (
                                SELECT order_id
                                FROM orders
                                WHERE user_id = ?
                            )
                        )
                   )

                 LIMIT 1"
            );

            if (!$stmt) {
                response(
                    false,
                    "Failed to prepare payment query",
                    null,
                    500
                );
            }

            $stmt->bind_param(
                "iii",
                $requestedPaymentId,
                $userId,
                $userId
            );

            if (!$stmt->execute()) {
                $message = $stmt->error;
                $stmt->close();

                response(
                    false,
                    $message,
                    null,
                    500
                );
            }

            $result = $stmt->get_result();

            if ($result->num_rows === 0) {
                $stmt->close();

                response(
                    false,
                    "Payment not found",
                    null,
                    404
                );
            }

            $payment =
                $result->fetch_assoc();

            $stmt->close();

            response(
                true,
                "Payment fetched successfully",
                [
                    $payment,
                ],
                200
            );
        }

        // ------------------------------------------------------
        // ALL USER PAYMENTS
        // ------------------------------------------------------

        $stmt = $con->prepare(
            "SELECT
                p.*,

                b.turf_id,
                b.slot_id,
                b.booking_date,
                b.status AS booking_status,

                t.turf_name,
                t.location,

                ts.start_time,
                ts.end_time

             FROM payments p

             LEFT JOIN bookings b
                ON b.booking_id = p.booking_id

             LEFT JOIN turf_tb t
                ON t.turf_id = b.turf_id

             LEFT JOIN turf_slots ts
                ON ts.slot_id = b.slot_id

             WHERE
                (
                    p.payment_type = 'turf'
                    AND b.user_id = ?
                )
                OR
                (
                    p.payment_type = 'product'
                    AND p.order_id IN (
                        SELECT order_id
                        FROM orders
                        WHERE user_id = ?
                    )
                )

             ORDER BY
                p.payment_id DESC"
        );

        if (!$stmt) {
            response(
                false,
                "Failed to prepare payment list",
                null,
                500
            );
        }

        $stmt->bind_param(
            "ii",
            $userId,
            $userId
        );

        if (!$stmt->execute()) {
            $message = $stmt->error;
            $stmt->close();

            response(
                false,
                $message,
                null,
                500
            );
        }

        $result =
            $stmt->get_result();

        $payments = [];

        while (
            $row =
                $result->fetch_assoc()
        ) {
            $payments[] = $row;
        }

        $stmt->close();

        response(
            true,
            "Payments fetched successfully",
            $payments,
            200
        );
    }

    // ========================================================
    // OWNER
    // ========================================================

    if ($role === "owner") {

        $stmt = $con->prepare(
            "SELECT
                p.*,

                b.user_id,
                b.turf_id,
                b.slot_id,
                b.booking_date,
                b.status AS booking_status,

                t.turf_name,
                t.location,

                ts.start_time,
                ts.end_time

             FROM payments p

             INNER JOIN bookings b
                ON b.booking_id = p.booking_id

             INNER JOIN turf_tb t
                ON t.turf_id = b.turf_id

             INNER JOIN turf_slots ts
                ON ts.slot_id = b.slot_id

             WHERE p.payment_type = 'turf'
               AND t.owner_id = ?

             ORDER BY p.payment_id DESC"
        );

        if (!$stmt) {
            response(
                false,
                "Failed to prepare owner payments",
                null,
                500
            );
        }

        $stmt->bind_param(
            "i",
            $userId
        );

        if (!$stmt->execute()) {
            $message = $stmt->error;
            $stmt->close();

            response(
                false,
                $message,
                null,
                500
            );
        }

        $result =
            $stmt->get_result();

        $payments = [];

        while (
            $row =
                $result->fetch_assoc()
        ) {
            $payments[] = $row;
        }

        $stmt->close();

        response(
            true,
            "Owner payments fetched successfully",
            $payments,
            200
        );
    }

    // ========================================================
    // ADMIN
    // ========================================================

    if ($role === "admin") {

        $stmt = $con->prepare(
            "SELECT
                p.*,

                b.user_id,
                b.turf_id,
                b.slot_id,
                b.booking_date,
                b.status AS booking_status,

                t.turf_name,
                t.location,

                ts.start_time,
                ts.end_time

             FROM payments p

             LEFT JOIN bookings b
                ON b.booking_id = p.booking_id

             LEFT JOIN turf_tb t
                ON t.turf_id = b.turf_id

             LEFT JOIN turf_slots ts
                ON ts.slot_id = b.slot_id

             ORDER BY p.payment_id DESC"
        );

        if (!$stmt) {
            response(
                false,
                "Failed to prepare admin payments",
                null,
                500
            );
        }

        if (!$stmt->execute()) {
            $message = $stmt->error;
            $stmt->close();

            response(
                false,
                $message,
                null,
                500
            );
        }

        $result =
            $stmt->get_result();

        $payments = [];

        while (
            $row =
                $result->fetch_assoc()
        ) {
            $payments[] = $row;
        }

        $stmt->close();

        response(
            true,
            "Admin payments fetched successfully",
            $payments,
            200
        );
    }
}

// ============================================================
// ADMIN - UPDATE PAYMENT STATUS
// ============================================================

if (
    $method === "PATCH" ||
    $method === "PUT"
) {

    if ($role !== "admin") {
        response(
            false,
            "Only admin can update payment status",
            null,
            403
        );
    }

    $paymentId = (int)(
        $data["payment_id"] ??
        0
    );

    $newStatus = strtolower(
        trim(
            (string)(
                $data["status"] ??
                ""
            )
        )
    );

    $allowedStatuses = [
        "pending",
        "success",
        "failed",
        "refunded",
    ];

    if (
        $paymentId <= 0 ||
        !in_array(
            $newStatus,
            $allowedStatuses,
            true
        )
    ) {
        response(
            false,
            "Valid payment_id and status are required",
            null,
            422
        );
    }

    $con->begin_transaction();

    try {

        // ========================================================
        // GET PAYMENT
        // ========================================================

        $stmt = $con->prepare(
            "SELECT
                payment_id,
                booking_id,
                order_id,
                payment_type,
                amount,
                status
             FROM payments
             WHERE payment_id = ?
             LIMIT 1
             FOR UPDATE"
        );

        if (!$stmt) {
            throw new Exception(
                $con->error
            );
        }

        $stmt->bind_param(
            "i",
            $paymentId
        );

        if (!$stmt->execute()) {
            throw new Exception(
                $stmt->error
            );
        }

        $result =
            $stmt->get_result();

        if ($result->num_rows === 0) {
            $stmt->close();

            throw new Exception(
                "Payment not found"
            );
        }

        $payment =
            $result->fetch_assoc();

        $stmt->close();

        // ========================================================
        // UPDATE PAYMENT
        // ========================================================

        $update = $con->prepare(
            "UPDATE payments
             SET status = ?
             WHERE payment_id = ?"
        );

        if (!$update) {
            throw new Exception(
                $con->error
            );
        }

        $update->bind_param(
            "si",
            $newStatus,
            $paymentId
        );

        if (!$update->execute()) {
            throw new Exception(
                $update->error
            );
        }

        $update->close();

        // ========================================================
        // TURF BOOKING STATUS
        // ========================================================

        $bookingId = (int)(
            $payment["booking_id"] ??
            0
        );

        if (
            $payment["payment_type"] === "turf" &&
            $bookingId > 0
        ) {

            if ($newStatus === "success") {

                $bookingUpdate =
                    $con->prepare(
                        "UPDATE bookings
                         SET status = 'paid'
                         WHERE booking_id = ?"
                    );

                if (!$bookingUpdate) {
                    throw new Exception(
                        $con->error
                    );
                }

                $bookingUpdate->bind_param(
                    "i",
                    $bookingId
                );

                if (
                    !$bookingUpdate->execute()
                ) {
                    throw new Exception(
                        $bookingUpdate->error
                    );
                }

                $bookingUpdate->close();

            } elseif (
                in_array(
                    $newStatus,
                    [
                        "failed",
                        "refunded",
                    ],
                    true
                )
            ) {

                $bookingUpdate =
                    $con->prepare(
                        "UPDATE bookings
                         SET status = 'pending'
                         WHERE booking_id = ?
                           AND status <> 'paid'"
                    );

                if (!$bookingUpdate) {
                    throw new Exception(
                        $con->error
                    );
                }

                $bookingUpdate->bind_param(
                    "i",
                    $bookingId
                );

                if (
                    !$bookingUpdate->execute()
                ) {
                    throw new Exception(
                        $bookingUpdate->error
                    );
                }

                $bookingUpdate->close();
            }
        }

        // ========================================================
        // PRODUCT ORDER STATUS
        // ========================================================

        $orderId = (int)(
            $payment["order_id"] ??
            0
        );

        if (
            $payment["payment_type"] === "product" &&
            $orderId > 0
        ) {

            if ($newStatus === "success") {

                $orderUpdate =
                    $con->prepare(
                        "UPDATE orders
                         SET status = 'paid'
                         WHERE order_id = ?"
                    );

                if (!$orderUpdate) {
                    throw new Exception(
                        $con->error
                    );
                }

                $orderUpdate->bind_param(
                    "i",
                    $orderId
                );

                if (
                    !$orderUpdate->execute()
                ) {
                    throw new Exception(
                        $orderUpdate->error
                    );
                }

                $orderUpdate->close();

            } elseif (
                in_array(
                    $newStatus,
                    [
                        "failed",
                        "refunded",
                    ],
                    true
                )
            ) {

                $orderUpdate =
                    $con->prepare(
                        "UPDATE orders
                         SET status = 'pending'
                         WHERE order_id = ?"
                    );

                if (!$orderUpdate) {
                    throw new Exception(
                        $con->error
                    );
                }

                $orderUpdate->bind_param(
                    "i",
                    $orderId
                );

                if (
                    !$orderUpdate->execute()
                ) {
                    throw new Exception(
                        $orderUpdate->error
                    );
                }

                $orderUpdate->close();
            }
        }

        $con->commit();

        response(
            true,
            "Payment status updated successfully",
            [
                "payment_id" =>
                    $paymentId,

                "booking_id" =>
                    $bookingId,

                "order_id" =>
                    $orderId,

                "status" =>
                    $newStatus,
            ],
            200
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
    "Unsupported request",
    null,
    405
);
?>