<?php

header("Content-Type: application/json; charset=UTF-8");
header("Cache-Control: no-store");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, OPTIONS");

if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(204);
    exit;
}

require_once __DIR__ . "/connection.php";
require_once __DIR__ . "/config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

function response(
    bool $status,
    string $message,
    $data = null,
    int $code = 200
): void {
    http_response_code($code);

    $out = [
        "status" => $status,
        "message" => $message
    ];

    if ($data !== null) {
        $out["data"] = $data;
    }

    echo json_encode($out);
    exit;
}

/*
|--------------------------------------------------------------------------
| INPUT
|--------------------------------------------------------------------------
*/

function inputData(): array
{
    $raw = file_get_contents("php://input");

    if ($raw === false || trim($raw) === "") {
        return [];
    }

    $data = json_decode($raw, true);

    return is_array($data) ? $data : [];
}

/*
|--------------------------------------------------------------------------
| AUTHORIZATION HEADER
|--------------------------------------------------------------------------
| Apache / Render may expose Authorization header using different
| server variables.
|--------------------------------------------------------------------------
*/

function getAuthorizationHeader(): string
{
    $header = "";

    if (!empty($_SERVER["HTTP_AUTHORIZATION"])) {
        $header = $_SERVER["HTTP_AUTHORIZATION"];
    }

    if ($header === "" &&
        !empty($_SERVER["REDIRECT_HTTP_AUTHORIZATION"])) {
        $header = $_SERVER["REDIRECT_HTTP_AUTHORIZATION"];
    }

    if ($header === "" &&
        function_exists("apache_request_headers")) {

        $headers = apache_request_headers();

        foreach ($headers as $key => $value) {
            if (strcasecmp($key, "Authorization") === 0) {
                $header = $value;
                break;
            }
        }
    }

    if ($header === "" &&
        function_exists("getallheaders")) {

        $headers = getallheaders();

        foreach ($headers as $key => $value) {
            if (strcasecmp($key, "Authorization") === 0) {
                $header = $value;
                break;
            }
        }
    }

    return trim($header);
}

/*
|--------------------------------------------------------------------------
| AUTHENTICATION
|--------------------------------------------------------------------------
*/

function authenticate(array $roles): array
{
    global $secret_key;

    $header = getAuthorizationHeader();

    if (!preg_match(
        "/^Bearer\s+(.+)$/i",
        $header,
        $matches
    )) {
        response(
            false,
            "Authorization token is required",
            null,
            401
        );
    }

    $token = trim($matches[1]);

    if ($token === "") {
        response(
            false,
            "Authorization token is required",
            null,
            401
        );
    }

    try {

        $payload = (array) JWT::decode(
            $token,
            new Key(
                $secret_key,
                "HS256"
            )
        );

        if (($payload["type"] ?? "") !== "access") {
            response(
                false,
                "Invalid access token",
                null,
                401
            );
        }

        $role = strtolower(
            (string)(
                $payload["role"] ?? ""
            )
        );

        if (!in_array(
            $role,
            $roles,
            true
        )) {
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

/*
|--------------------------------------------------------------------------
| HELPERS
|--------------------------------------------------------------------------
*/

function money($value): float
{
    return round(
        (float)$value,
        2
    );
}

function arraysEqualFloat(
    float $a,
    float $b
): bool {
    return abs($a - $b) < 0.01;
}

/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

if (!isset($con) ||
    $con->connect_error) {

    response(
        false,
        "Database connection failed",
        null,
        500
    );
}

/*
|--------------------------------------------------------------------------
| AUTH
|--------------------------------------------------------------------------
*/

$method = $_SERVER["REQUEST_METHOD"];

$payload = authenticate([
    "user",
    "owner",
    "admin"
]);

$role = strtolower(
    (string)(
        $payload["role"] ?? ""
    )
);

$userId = (int)(
    $payload["user_id"] ??
    $payload["id"] ??
    0
);

$data = inputData();

/*
|--------------------------------------------------------------------------
| GET PAYMENT
|--------------------------------------------------------------------------
*/

if ($method === "GET") {

    $paymentId = (int)(
        $_GET["payment_id"] ?? 0
    );

    $bookingId = (int)(
        $_GET["booking_id"] ?? 0
    );

    $orderId = (int)(
        $_GET["order_id"] ?? 0
    );

    if ($role === "user") {

        $where = [];
        $params = [];
        $types = "";

        $where[] = "p.user_id = ?";
        $params[] = $userId;
        $types .= "i";

        if ($paymentId > 0) {
            $where[] = "p.payment_id = ?";
            $params[] = $paymentId;
            $types .= "i";
        }

        if ($bookingId > 0) {
            $where[] = "p.booking_id = ?";
            $params[] = $bookingId;
            $types .= "i";
        }

        if ($orderId > 0) {
            $where[] = "p.order_id = ?";
            $params[] = $orderId;
            $types .= "i";
        }

        $sql =
            "SELECT
                p.*
             FROM payments p
             WHERE " .
            implode(
                " AND ",
                $where
            ) .
            " ORDER BY p.payment_id DESC";

        $stmt = $con->prepare($sql);

        if (!$stmt) {
            response(
                false,
                "Failed to prepare payment query",
                null,
                500
            );
        }

        $stmt->bind_param(
            $types,
            ...$params
        );

    } elseif ($role === "owner") {

        $stmt = $con->prepare(
            "SELECT p.*
             FROM payments p
             JOIN bookings b
               ON b.booking_id = p.booking_id
             JOIN turf_tb t
               ON t.turf_id = b.turf_id
             WHERE t.owner_id = ?
             ORDER BY p.payment_id DESC"
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
            "i",
            $userId
        );

    } else {

        $stmt = $con->prepare(
            "SELECT p.*
             FROM payments p
             ORDER BY p.payment_id DESC"
        );

        if (!$stmt) {
            response(
                false,
                "Failed to prepare payment query",
                null,
                500
            );
        }
    }

    $stmt->execute();

    $result = $stmt->get_result();

    $payments = [];

    while ($row = $result->fetch_assoc()) {

        $row["payment_id"] =
            (int)$row["payment_id"];

        if (isset($row["user_id"])) {
            $row["user_id"] =
                (int)$row["user_id"];
        }

        if (isset($row["booking_id"])) {
            $row["booking_id"] =
                (int)$row["booking_id"];
        }

        if (isset($row["order_id"])) {
            $row["order_id"] =
                (int)$row["order_id"];
        }

        $row["amount"] =
            money($row["amount"]);

        $payments[] = $row;
    }

    $stmt->close();

    if (count($payments) === 0) {
        response(
            false,
            "Payment not found",
            null,
            404
        );
    }

    if ($paymentId > 0 ||
        $bookingId > 0 ||
        $orderId > 0) {

        response(
            true,
            "Payment fetched successfully",
            $payments[0]
        );
    }

    response(
        true,
        "Payments fetched successfully",
        $payments
    );
}

/*
|--------------------------------------------------------------------------
| POST
|--------------------------------------------------------------------------
| action=initiate
| action=finalize
|--------------------------------------------------------------------------
*/

if ($method === "POST") {

    if ($role !== "user") {
        response(
            false,
            "Only users can make payments",
            null,
            403
        );
    }

    $action = strtolower(
        trim(
            (string)(
                $data["action"] ??
                "initiate"
            )
        )
    );

    /*
    |--------------------------------------------------------------------------
    | INITIATE PAYMENT
    |--------------------------------------------------------------------------
    */

    if ($action === "initiate") {

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

        $transactionId = trim(
            (string)(
                $data["transaction_id"] ??
                ""
            )
        );

        $clientAmount = money(
            $data["amount"] ?? 0
        );

        if (!in_array(
            $paymentType,
            ["turf", "product"],
            true
        )) {
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

        if ($transactionId === "") {
            response(
                false,
                "transaction_id is required",
                null,
                422
            );
        }

        /*
        |--------------------------------------------------------------------------
        | DUPLICATE TRANSACTION
        |--------------------------------------------------------------------------
        */

        $duplicate = $con->prepare(
            "SELECT payment_id
             FROM payments
             WHERE transaction_id = ?
             LIMIT 1"
        );

        if ($duplicate) {

            $duplicate->bind_param(
                "s",
                $transactionId
            );

            $duplicate->execute();

            $duplicateResult =
                $duplicate->get_result();

            if ($duplicateResult->num_rows > 0) {

                $existing =
                    $duplicateResult->fetch_assoc();

                $duplicate->close();

                response(
                    true,
                    "Payment already initiated",
                    [
                        "payment_id" =>
                            (int)$existing["payment_id"],
                        "transaction_id" =>
                            $transactionId
                    ]
                );
            }

            $duplicate->close();
        }

        $con->begin_transaction();

        try {

            $serverAmount = 0.0;
            $bookingId = null;
            $orderId = null;

            /*
            |--------------------------------------------------------------------------
            | TURF PAYMENT
            |--------------------------------------------------------------------------
            */

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
                        booking_id,
                        amount,
                        status
                     FROM bookings
                     WHERE booking_id = ?
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
                    $bookingId,
                    $userId
                );

                $stmt->execute();

                $result =
                    $stmt->get_result();

                if ($result->num_rows === 0) {

                    $stmt->close();

                    throw new Exception(
                        "Booking not found"
                    );
                }

                $booking =
                    $result->fetch_assoc();

                $stmt->close();

                $bookingStatus =
                    strtolower(
                        (string)(
                            $booking["status"] ??
                            ""
                        )
                    );

                if (in_array(
                    $bookingStatus,
                    [
                        "paid",
                        "completed"
                    ],
                    true
                )) {
                    throw new Exception(
                        "Booking is already paid"
                    );
                }

                $serverAmount =
                    money(
                        $booking["amount"]
                    );

                if ($clientAmount > 0 &&
                    !arraysEqualFloat(
                        $clientAmount,
                        $serverAmount
                    )) {

                    throw new Exception(
                        "Payment amount does not match booking amount"
                    );
                }
            }

            /*
            |--------------------------------------------------------------------------
            | PRODUCT PAYMENT
            |--------------------------------------------------------------------------
            |
            | Product order is already created by order_api.php.
            | We use order_id instead of asking Flutter to send
            | product items again.
            |--------------------------------------------------------------------------
            */

            if ($paymentType === "product") {

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
                        product_id,
                        quantity,
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

                $stmt->execute();

                $result =
                    $stmt->get_result();

                if ($result->num_rows === 0) {

                    $stmt->close();

                    throw new Exception(
                        "Order not found"
                    );
                }

                $order =
                    $result->fetch_assoc();

                $stmt->close();

                $orderStatus =
                    strtolower(
                        (string)(
                            $order["status"] ??
                            ""
                        )
                    );

                if ($orderStatus === "paid") {
                    throw new Exception(
                        "Order is already paid"
                    );
                }

                if (in_array(
                    $orderStatus,
                    [
                        "cancelled",
                        "canceled"
                    ],
                    true
                )) {
                    throw new Exception(
                        "Order has been cancelled"
                    );
                }

                /*
                order_api.php already created the order
                and stored the product line amount.

                Delivery:
                >= ₹1000 -> free
                < ₹1000  -> ₹40
                */

                $subtotal =
                    money(
                        $order["amount"]
                    );

                $deliveryFee =
                    $subtotal >= 1000
                        ? 0.0
                        : 40.0;

                $serverAmount =
                    money(
                        $subtotal +
                        $deliveryFee
                    );

                /*
                If Flutter sends amount, validate it.
                If it doesn't, server amount is used.
                */

                if ($clientAmount > 0 &&
                    !arraysEqualFloat(
                        $clientAmount,
                        $serverAmount
                    )) {

                    throw new Exception(
                        "Payment amount does not match order amount"
                    );
                }
            }

            /*
            |--------------------------------------------------------------------------
            | CREATE PENDING PAYMENT
            |--------------------------------------------------------------------------
            */

            $insert = $con->prepare(
                "INSERT INTO payments
                (
                    user_id,
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
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    'pending',
                    NOW()
                )"
            );

            if (!$insert) {
                throw new Exception(
                    $con->error
                );
            }

            $insert->bind_param(
                "iiisdss",
                $userId,
                $bookingId,
                $orderId,
                $paymentType,
                $serverAmount,
                $paymentMethod,
                $transactionId
            );

            if (!$insert->execute()) {

                $error =
                    $insert->error;

                $insert->close();

                throw new Exception(
                    $error
                );
            }

            $paymentId =
                (int)$insert->insert_id;

            $insert->close();

            $con->commit();

            response(
                true,
                "Payment initiated successfully",
                [
                    "payment_id" =>
                        $paymentId,
                    "payment_type" =>
                        $paymentType,
                    "booking_id" =>
                        $bookingId,
                    "order_id" =>
                        $orderId,
                    "amount" =>
                        $serverAmount,
                    "payment_method" =>
                        $paymentMethod,
                    "transaction_id" =>
                        $transactionId,
                    "status" =>
                        "pending"
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

    /*
    |--------------------------------------------------------------------------
    | FINALIZE PAYMENT
    |--------------------------------------------------------------------------
    */

    if ($action === "finalize") {

        $paymentId = (int)(
            $data["payment_id"] ??
            0
        );

        $transactionId = trim(
            (string)(
                $data["transaction_id"] ??
                ""
            )
        );

        if ($paymentId <= 0) {
            response(
                false,
                "payment_id is required",
                null,
                422
            );
        }

        if ($transactionId === "") {
            response(
                false,
                "transaction_id is required",
                null,
                422
            );
        }

        $con->begin_transaction();

        try {

            $stmt = $con->prepare(
                "SELECT *
                 FROM payments
                 WHERE payment_id = ?
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
                $paymentId,
                $userId
            );

            $stmt->execute();

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

            if ((string)$payment["transaction_id"] !==
                $transactionId) {

                throw new Exception(
                    "Payment reference mismatch"
                );
            }

            $paymentStatus =
                strtolower(
                    (string)(
                        $payment["status"] ??
                        ""
                    )
                );

            if ($paymentStatus !== "success") {

                throw new Exception(
                    "Payment is not verified yet"
                );
            }

            $paymentType =
                strtolower(
                    (string)(
                        $payment["payment_type"] ??
                        ""
                    )
                );

            /*
            |--------------------------------------------------------------------------
            | TURF FINALIZE
            |--------------------------------------------------------------------------
            */

            if ($paymentType === "turf") {

                $bookingId =
                    (int)(
                        $payment["booking_id"] ??
                        0
                    );

                if ($bookingId <= 0) {
                    throw new Exception(
                        "Payment booking ID is missing"
                    );
                }

                $booking =
                    $con->prepare(
                        "SELECT
                            booking_id,
                            status,
                            amount
                         FROM bookings
                         WHERE booking_id = ?
                           AND user_id = ?
                         LIMIT 1
                         FOR UPDATE"
                    );

                if (!$booking) {
                    throw new Exception(
                        $con->error
                    );
                }

                $booking->bind_param(
                    "ii",
                    $bookingId,
                    $userId
                );

                $booking->execute();

                $bookingResult =
                    $booking->get_result();

                if ($bookingResult->num_rows === 0) {

                    $booking->close();

                    throw new Exception(
                        "Booking not found"
                    );
                }

                $bookingRow =
                    $bookingResult->fetch_assoc();

                $booking->close();

                $bookingStatus =
                    strtolower(
                        (string)(
                            $bookingRow["status"] ??
                            ""
                        )
                    );

                if ($bookingStatus !== "paid") {

                    $update =
                        $con->prepare(
                            "UPDATE bookings
                             SET status = 'paid'
                             WHERE booking_id = ?
                               AND user_id = ?"
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

                    if (!$update->execute()) {
                        throw new Exception(
                            $update->error
                        );
                    }

                    $update->close();
                }

                $con->commit();

                response(
                    true,
                    "Turf payment finalized successfully",
                    [
                        "payment_id" =>
                            $paymentId,
                        "booking_id" =>
                            $bookingId,
                        "amount" =>
                            money(
                                $payment["amount"]
                            ),
                        "status" =>
                            "success"
                    ]
                );
            }

            /*
            |--------------------------------------------------------------------------
            | PRODUCT FINALIZE
            |--------------------------------------------------------------------------
            |
            | IMPORTANT:
            | order_api.php already created the order and deducted
            | stock. So we DO NOT create another order here.
            |--------------------------------------------------------------------------
            */

            if ($paymentType === "product") {

                $orderId =
                    (int)(
                        $payment["order_id"] ??
                        0
                    );

                if ($orderId <= 0) {
                    throw new Exception(
                        "Payment order ID is missing"
                    );
                }

                $orderStmt =
                    $con->prepare(
                        "SELECT
                            order_id,
                            user_id,
                            product_id,
                            quantity,
                            amount,
                            status
                         FROM orders
                         WHERE order_id = ?
                           AND user_id = ?
                         LIMIT 1
                         FOR UPDATE"
                    );

                if (!$orderStmt) {
                    throw new Exception(
                        $con->error
                    );
                }

                $orderStmt->bind_param(
                    "ii",
                    $orderId,
                    $userId
                );

                $orderStmt->execute();

                $orderResult =
                    $orderStmt->get_result();

                if ($orderResult->num_rows === 0) {

                    $orderStmt->close();

                    throw new Exception(
                        "Order not found"
                    );
                }

                $order =
                    $orderResult->fetch_assoc();

                $orderStmt->close();

                $orderStatus =
                    strtolower(
                        (string)(
                            $order["status"] ??
                            ""
                        )
                    );

                if ($orderStatus === "cancelled" ||
                    $orderStatus === "canceled") {

                    throw new Exception(
                        "Order has been cancelled"
                    );
                }

                /*
                Order was already created by order_api.php.
                Just change pending -> paid.
                */

                if ($orderStatus !== "paid") {

                    $updateOrder =
                        $con->prepare(
                            "UPDATE orders
                             SET status = 'paid'
                             WHERE order_id = ?
                               AND user_id = ?"
                        );

                    if (!$updateOrder) {
                        throw new Exception(
                            $con->error
                        );
                    }

                    $updateOrder->bind_param(
                        "ii",
                        $orderId,
                        $userId
                    );

                    if (!$updateOrder->execute()) {
                        throw new Exception(
                            $updateOrder->error
                        );
                    }

                    $updateOrder->close();
                }

                $con->commit();

                response(
                    true,
                    "Product payment finalized successfully",
                    [
                        "payment_id" =>
                            $paymentId,
                        "order_id" =>
                            $orderId,
                        "total_amount" =>
                            money(
                                $payment["amount"]
                            ),
                        "orders" => [
                            [
                                "order_id" =>
                                    $orderId,
                                "product_id" =>
                                    (int)$order["product_id"],
                                "quantity" =>
                                    (int)$order["quantity"],
                                "amount" =>
                                    money(
                                        $order["amount"]
                                    ),
                                "status" =>
                                    "paid"
                            ]
                        ],
                        "status" =>
                            "success"
                    ]
                );
            }

            throw new Exception(
                "Unsupported payment type"
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

    response(
        false,
        "Unsupported payment action",
        null,
        422
    );
}

/*
|--------------------------------------------------------------------------
| ADMIN PAYMENT STATUS
|--------------------------------------------------------------------------
*/

if ($method === "PATCH" ||
    $method === "PUT") {

    if ($role !== "admin") {

        response(
            false,
            "Only admin can update payment status",
            null,
            403
        );
    }

    $paymentId =
        (int)(
            $data["payment_id"] ??
            0
        );

    $status =
        strtolower(
            trim(
                (string)(
                    $data["status"] ??
                    ""
                )
            )
        );

    $allowed = [
        "pending",
        "success",
        "failed",
        "refunded"
    ];

    if ($paymentId <= 0 ||
        !in_array(
            $status,
            $allowed,
            true
        )) {

        response(
            false,
            "Valid payment_id and status are required",
            null,
            422
        );
    }

    $con->begin_transaction();

    try {

        $stmt =
            $con->prepare(
                "SELECT
                    payment_id,
                    booking_id,
                    order_id,
                    payment_type
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

        $stmt->execute();

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

        $update =
            $con->prepare(
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
            $status,
            $paymentId
        );

        if (!$update->execute()) {
            throw new Exception(
                $update->error
            );
        }

        $update->close();

        /*
        Turf payment:
        admin success can directly mark booking paid.

        Product payment:
        order will be marked paid through finalize.
        */

        if (
            $status === "success" &&
            strtolower(
                (string)$payment["payment_type"]
            ) === "turf"
        ) {

            $bookingId =
                (int)(
                    $payment["booking_id"] ??
                    0
                );

            if ($bookingId > 0) {

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

                if (!$bookingUpdate->execute()) {
                    throw new Exception(
                        $bookingUpdate->error
                    );
                }

                $bookingUpdate->close();
            }
        }

        $con->commit();

        response(
            true,
            "Payment status updated successfully",
            [
                "payment_id" =>
                    $paymentId,
                "status" =>
                    $status
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

/*
|--------------------------------------------------------------------------
| UNSUPPORTED
|--------------------------------------------------------------------------
*/

response(
    false,
    "Unsupported request",
    null,
    405
);