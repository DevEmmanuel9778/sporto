<?php

header("Content-Type: application/json; charset=UTF-8");
header("Cache-Control: no-store");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS");

if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(204);
    exit;
}

require_once __DIR__ . "/connection.php";
require_once __DIR__ . "/config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function response(bool $status, string $message, $data = null, int $code = 200): void
{
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

function inputData(): array
{
    $raw = file_get_contents("php://input");

    if ($raw === false || trim($raw) === "") {
        return [];
    }

    $decoded = json_decode($raw, true);

    return is_array($decoded) ? $decoded : [];
}

function authenticate(array $allowedRoles): array
{
    global $secret_key;

    $header = $_SERVER["HTTP_AUTHORIZATION"] ?? "";

    if (!preg_match("/Bearer\s+(.+)/i", $header, $matches)) {
        response(false, "Authorization token is required", null, 401);
    }

    try {
        $payload = (array) JWT::decode(
            trim($matches[1]),
            new Key($secret_key, "HS256")
        );

        if (($payload["type"] ?? "") !== "access") {
            response(false, "Invalid access token", null, 401);
        }

        $role = strtolower((string)($payload["role"] ?? ""));

        if (!in_array($role, $allowedRoles, true)) {
            response(false, "Access denied", null, 403);
        }

        return $payload;
    } catch (Throwable $e) {
        response(false, "Invalid or expired token", null, 401);
    }

    return [];
}

function intValue($value): int
{
    return (int)$value;
}

function money($value): float
{
    return round((float)$value, 2);
}

set_exception_handler(function (Throwable $e) {
    response(
        false,
        "Server error: " . $e->getMessage(),
        null,
        500
    );
});

if (!isset($con) || $con->connect_error) {
    response(false, "Database connection failed", null, 500);
}

$method = $_SERVER["REQUEST_METHOD"];
$user = authenticate(["user", "admin"]);

$role = strtolower((string)($user["role"] ?? ""));
$userId = (int)($user["user_id"] ?? $user["id"] ?? 0);

$data = inputData();

if ($userId <= 0) {
    response(false, "Invalid user ID", null, 401);
}

/*
|--------------------------------------------------------------------------
| GET
|--------------------------------------------------------------------------
| User:
|   /order_api.php
|   /order_api.php?order_id=123
|
| Admin:
|   all orders
|   or one order with order_id
*/

if ($method === "GET") {
    $orderId = (int)($_GET["order_id"] ?? 0);

    if ($role === "user") {
        if ($orderId > 0) {
            $stmt = $con->prepare(
                "SELECT
                    o.*,
                    p.name AS product_name,
                    p.category,
                    p.image
                 FROM orders o
                 JOIN products p
                   ON p.product_id = o.product_id
                 WHERE o.user_id = ?
                   AND o.order_id = ?
                 LIMIT 1"
            );

            if (!$stmt) {
                response(false, "Failed to prepare order query", null, 500);
            }

            $stmt->bind_param(
                "ii",
                $userId,
                $orderId
            );
        } else {
            $stmt = $con->prepare(
                "SELECT
                    o.*,
                    p.name AS product_name,
                    p.category,
                    p.image
                 FROM orders o
                 JOIN products p
                   ON p.product_id = o.product_id
                 WHERE o.user_id = ?
                 ORDER BY o.order_date DESC, o.order_id DESC"
            );

            if (!$stmt) {
                response(false, "Failed to prepare orders query", null, 500);
            }

            $stmt->bind_param(
                "i",
                $userId
            );
        }
    } else {
        if ($orderId > 0) {
            $stmt = $con->prepare(
                "SELECT
                    o.*,
                    p.name AS product_name,
                    p.category,
                    p.image
                 FROM orders o
                 JOIN products p
                   ON p.product_id = o.product_id
                 WHERE o.order_id = ?
                 LIMIT 1"
            );

            if (!$stmt) {
                response(false, "Failed to prepare order query", null, 500);
            }

            $stmt->bind_param(
                "i",
                $orderId
            );
        } else {
            $stmt = $con->prepare(
                "SELECT
                    o.*,
                    p.name AS product_name,
                    p.category,
                    p.image
                 FROM orders o
                 JOIN products p
                   ON p.product_id = o.product_id
                 ORDER BY o.order_date DESC, o.order_id DESC"
            );

            if (!$stmt) {
                response(false, "Failed to prepare orders query", null, 500);
            }
        }
    }

    $stmt->execute();

    $result = $stmt->get_result();

    $orders = [];

    while ($row = $result->fetch_assoc()) {
        $row["order_id"] = (int)$row["order_id"];
        $row["user_id"] = (int)$row["user_id"];
        $row["product_id"] = (int)$row["product_id"];
        $row["quantity"] = (int)$row["quantity"];
        $row["amount"] = money($row["amount"]);

        $orders[] = $row;
    }

    $stmt->close();

    if ($orderId > 0) {
        if (count($orders) === 0) {
            response(false, "Order not found", null, 404);
        }

        response(
            true,
            "Order fetched successfully",
            $orders[0]
        );
    }

    response(
        true,
        "Orders fetched successfully",
        $orders
    );
}

/*
|--------------------------------------------------------------------------
| POST
|--------------------------------------------------------------------------
| Legacy/direct order creation endpoint.
|
| Store checkout should use payment_api.php finalize flow instead.
*/

if ($method === "POST") {
    if ($role !== "user") {
        response(
            false,
            "Only users can create orders",
            null,
            403
        );
    }

    $items = $data["items"] ?? [];

    if (!is_array($items) || count($items) === 0) {
        response(
            false,
            "Order items are required",
            null,
            422
        );
    }

    $con->begin_transaction();

    try {
        $created = [];
        $total = 0.0;

        foreach ($items as $item) {
            $productId =
                (int)($item["product_id"] ?? 0);

            $qty =
                (int)($item["quantity"] ?? 0);

            if ($productId <= 0 ||
                $qty <= 0) {
                throw new Exception(
                    "Invalid product_id or quantity"
                );
            }

            $stmt = $con->prepare(
                "SELECT
                    product_id,
                    name,
                    price,
                    stock,
                    status
                 FROM products
                 WHERE product_id = ?
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
                $productId
            );

            $stmt->execute();

            $result =
                $stmt->get_result();

            if ($result->num_rows === 0) {
                $stmt->close();

                throw new Exception(
                    "Product not found"
                );
            }

            $product =
                $result->fetch_assoc();

            $stmt->close();

            if (strtolower(
                    (string)$product["status"]
                ) !== "available") {
                throw new Exception(
                    "Product is not available: " .
                    $product["name"]
                );
            }

            if ((int)$product["stock"] < $qty) {
                throw new Exception(
                    "Insufficient stock: " .
                    $product["name"]
                );
            }

            $amount =
                money(
                    (float)$product["price"] *
                    $qty
                );

            $insert = $con->prepare(
                "INSERT INTO orders
                (
                    user_id,
                    product_id,
                    quantity,
                    amount,
                    status,
                    order_date
                )
                VALUES (?, ?, ?, ?, 'pending', CURDATE())"
            );

            if (!$insert) {
                throw new Exception(
                    $con->error
                );
            }

            $insert->bind_param(
                "iiid",
                $userId,
                $productId,
                $qty,
                $amount
            );

            if (!$insert->execute()) {
                $error =
                    $insert->error;

                $insert->close();

                throw new Exception(
                    $error
                );
            }

            $orderId =
                (int)$insert->insert_id;

            $insert->close();

            $stock =
                $con->prepare(
                    "UPDATE products
                     SET stock = stock - ?
                     WHERE product_id = ?"
                );

            if (!$stock) {
                throw new Exception(
                    $con->error
                );
            }

            $stock->bind_param(
                "ii",
                $qty,
                $productId
            );

            if (!$stock->execute()) {
                throw new Exception(
                    $stock->error
                );
            }

            $stock->close();

            $total += $amount;

            $created[] = [
                "order_id" => $orderId,
                "product_id" => $productId,
                "product_name" =>
                    $product["name"],
                "quantity" => $qty,
                "amount" => $amount,
                "status" => "pending"
            ];
        }

        $con->commit();

        response(
            true,
            "Order created successfully",
            [
                "user_id" => $userId,
                "total_amount" =>
                    money($total),
                "orders" => $created
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
| ADMIN UPDATE
|--------------------------------------------------------------------------
*/

if ($method === "PATCH" ||
    $method === "PUT") {

    if ($role !== "admin") {
        response(
            false,
            "Only admin can update order status",
            null,
            403
        );
    }

    $orderId =
        (int)($data["order_id"] ?? 0);

    $status =
        strtolower(
            trim(
                (string)(
                    $data["status"] ?? ""
                )
            )
        );

    $allowed = [
        "pending",
        "paid",
        "processing",
        "shipped",
        "delivered",
        "cancelled"
    ];

    if ($orderId <= 0 ||
        !in_array($status, $allowed, true)) {

        response(
            false,
            "Valid order_id and status are required",
            null,
            422
        );
    }

    $stmt = $con->prepare(
        "UPDATE orders
         SET status = ?
         WHERE order_id = ?"
    );

    if (!$stmt) {
        response(
            false,
            "Failed to prepare order update",
            null,
            500
        );
    }

    $stmt->bind_param(
        "si",
        $status,
        $orderId
    );

    if (!$stmt->execute()) {
        $error = $stmt->error;

        $stmt->close();

        response(
            false,
            $error,
            null,
            500
        );
    }

    if ($stmt->affected_rows === 0) {
        $stmt->close();

        response(
            false,
            "Order not found",
            null,
            404
        );
    }

    $stmt->close();

    response(
        true,
        "Order status updated successfully"
    );
}

/*
|--------------------------------------------------------------------------
| USER CANCEL
|--------------------------------------------------------------------------
*/

if ($method === "DELETE") {
    if ($role !== "user") {
        response(
            false,
            "Only users can cancel their orders",
            null,
            403
        );
    }

    $orderId =
        (int)(
            $data["order_id"] ??
            $_GET["order_id"] ??
            0
        );

    if ($orderId <= 0) {
        response(
            false,
            "order_id is required",
            null,
            422
        );
    }

    $con->begin_transaction();

    try {
        $stmt = $con->prepare(
            "SELECT
                product_id,
                quantity,
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

        if (strtolower(
                (string)$order["status"]
            ) !== "pending") {

            throw new Exception(
                "Only pending orders can be cancelled"
            );
        }

        $update = $con->prepare(
            "UPDATE orders
             SET status = 'cancelled'
             WHERE order_id = ?
               AND user_id = ?"
        );

        if (!$update) {
            throw new Exception(
                $con->error
            );
        }

        $update->bind_param(
            "ii",
            $orderId,
            $userId
        );

        if (!$update->execute()) {
            throw new Exception(
                $update->error
            );
        }

        $update->close();

        $productId =
            (int)$order["product_id"];

        $qty =
            (int)$order["quantity"];

        $restore = $con->prepare(
            "UPDATE products
             SET stock = stock + ?
             WHERE product_id = ?"
        );

        if (!$restore) {
            throw new Exception(
                $con->error
            );
        }

        $restore->bind_param(
            "ii",
            $qty,
            $productId
        );

        if (!$restore->execute()) {
            throw new Exception(
                $restore->error
            );
        }

        $restore->close();

        $con->commit();

        response(
            true,
            "Order cancelled successfully"
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
    "Unsupported request",
    null,
    405
);