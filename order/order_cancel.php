<?php

header("Content-Type: application/json");

require_once '../connection.php';
require_once '../config/jwt.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode([
        "status" => false,
        "message" => "Only POST method is allowed"
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| Get Authorization Header
|--------------------------------------------------------------------------
*/

$headers = getallheaders();
$authHeader = $headers['Authorization'] ?? '';

if (empty($authHeader)) {
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

$token = $matches[1];

/*
|--------------------------------------------------------------------------
| Verify JWT
|--------------------------------------------------------------------------
*/

try {

    $decoded = JWT::decode(
        $token,
        new Key($secret_key, 'HS256')
    );

    if (!isset($decoded->data->id) || !isset($decoded->data->role)) {
        echo json_encode([
            "status" => false,
            "message" => "Invalid token"
        ]);
        exit;
    }

    $user_id = (int)$decoded->data->id;
    $role = $decoded->data->role;

    if ($role !== 'user') {
        echo json_encode([
            "status" => false,
            "message" => "Only users can cancel orders"
        ]);
        exit;
    }

} catch (Throwable $e) {

    echo json_encode([
        "status" => false,
        "message" => "Invalid or expired token"
    ]);

    exit;
}

/*
|--------------------------------------------------------------------------
| Get Order ID
|--------------------------------------------------------------------------
*/

$order_id = $_POST['order_id'] ?? '';

if ($order_id === '' || !is_numeric($order_id)) {

    echo json_encode([
        "status" => false,
        "message" => "Valid order ID is required"
    ]);

    exit;
}

$order_id = (int)$order_id;

/*
|--------------------------------------------------------------------------
| Start Transaction
|--------------------------------------------------------------------------
*/

mysqli_begin_transaction($con);

try {

    /*
    |----------------------------------------------------------------------
    | Get Order and Lock Row
    |----------------------------------------------------------------------
    */

    $query = "SELECT id, product_id, quantity, status
              FROM orders
              WHERE id = ?
              AND user_id = ?
              FOR UPDATE";

    $stmt = mysqli_prepare($con, $query);

    if (!$stmt) {
        throw new Exception("Database query failed");
    }

    mysqli_stmt_bind_param(
        $stmt,
        "ii",
        $order_id,
        $user_id
    );

    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) === 0) {

        mysqli_stmt_close($stmt);

        throw new Exception("Order not found");
    }

    $order = mysqli_fetch_assoc($result);

    mysqli_stmt_close($stmt);

    /*
    |----------------------------------------------------------------------
    | Check Order Status
    |----------------------------------------------------------------------
    */

    if ($order['status'] === 'cancelled') {

        throw new Exception("Order is already cancelled");
    }

    if (
        $order['status'] !== 'pending' &&
        $order['status'] !== 'confirmed'
    ) {

        throw new Exception(
            "This order cannot be cancelled"
        );
    }

    $product_id = (int)$order['product_id'];
    $quantity = (int)$order['quantity'];

    /*
    |----------------------------------------------------------------------
    | Lock Product
    |----------------------------------------------------------------------
    */

    $query = "SELECT id
              FROM products
              WHERE id = ?
              FOR UPDATE";

    $stmt = mysqli_prepare($con, $query);

    if (!$stmt) {
        throw new Exception("Failed to check product");
    }

    mysqli_stmt_bind_param(
        $stmt,
        "i",
        $product_id
    );

    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) === 0) {

        mysqli_stmt_close($stmt);

        throw new Exception("Product not found");
    }

    mysqli_stmt_close($stmt);

    /*
    |----------------------------------------------------------------------
    | Restore Stock
    |----------------------------------------------------------------------
    */

    $query = "UPDATE products
              SET stock = stock + ?
              WHERE id = ?";

    $stmt = mysqli_prepare($con, $query);

    if (!$stmt) {
        throw new Exception("Failed to restore stock");
    }

    mysqli_stmt_bind_param(
        $stmt,
        "ii",
        $quantity,
        $product_id
    );

    if (!mysqli_stmt_execute($stmt)) {

        mysqli_stmt_close($stmt);

        throw new Exception("Failed to restore stock");
    }

    mysqli_stmt_close($stmt);

    /*
    |----------------------------------------------------------------------
    | Cancel Order
    |----------------------------------------------------------------------
    */

    $query = "UPDATE orders
              SET status = 'cancelled'
              WHERE id = ?
              AND user_id = ?";

    $stmt = mysqli_prepare($con, $query);

    if (!$stmt) {
        throw new Exception("Failed to cancel order");
    }

    mysqli_stmt_bind_param(
        $stmt,
        "ii",
        $order_id,
        $user_id
    );

    if (!mysqli_stmt_execute($stmt)) {

        mysqli_stmt_close($stmt);

        throw new Exception("Failed to cancel order");
    }

    mysqli_stmt_close($stmt);

    /*
    |----------------------------------------------------------------------
    | Commit
    |----------------------------------------------------------------------
    */

    mysqli_commit($con);

    echo json_encode([
        "status" => true,
        "message" => "Order cancelled successfully",
        "order_id" => $order_id
    ]);

} catch (Throwable $e) {

    mysqli_rollback($con);

    echo json_encode([
        "status" => false,
        "message" => $e->getMessage()
    ]);
}

?>