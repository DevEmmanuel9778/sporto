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
            "message" => "Only users can place orders"
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
| Get Request Data
|--------------------------------------------------------------------------
*/

$product_id = $_POST['product_id'] ?? '';
$quantity = $_POST['quantity'] ?? '';

if ($product_id === '' || !is_numeric($product_id)) {
    echo json_encode([
        "status" => false,
        "message" => "Valid product ID is required"
    ]);
    exit;
}

if ($quantity === '' || !is_numeric($quantity)) {
    echo json_encode([
        "status" => false,
        "message" => "Valid quantity is required"
    ]);
    exit;
}

$product_id = (int)$product_id;
$quantity = (int)$quantity;

if ($quantity <= 0) {
    echo json_encode([
        "status" => false,
        "message" => "Quantity must be greater than zero"
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| Start Transaction
|--------------------------------------------------------------------------
*/

mysqli_begin_transaction($con);

try {

    /*
    |----------------------------------------------------------------------
    | Get Product and Lock Row
    |----------------------------------------------------------------------
    */

    $query = "SELECT id, name, price, stock, status
              FROM products
              WHERE id = ?
              FOR UPDATE";

    $stmt = mysqli_prepare($con, $query);

    if (!$stmt) {
        throw new Exception("Database query failed");
    }

    mysqli_stmt_bind_param($stmt, "i", $product_id);
    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) === 0) {
        mysqli_stmt_close($stmt);
        throw new Exception("Product not found");
    }

    $product = mysqli_fetch_assoc($result);

    mysqli_stmt_close($stmt);

    /*
    |----------------------------------------------------------------------
    | Check Product Status
    |----------------------------------------------------------------------
    */

    if ($product['status'] !== 'active') {
        throw new Exception("Product is not available");
    }

    /*
    |----------------------------------------------------------------------
    | Check Stock
    |----------------------------------------------------------------------
    */

    if ((int)$product['stock'] < $quantity) {
        throw new Exception("Insufficient stock");
    }

    /*
    |----------------------------------------------------------------------
    | Calculate Amount
    |----------------------------------------------------------------------
    */

    $price = (float)$product['price'];
    $amount = $price * $quantity;

    /*
    |----------------------------------------------------------------------
    | Create Order
    |----------------------------------------------------------------------
    */

    $query = "INSERT INTO orders
              (user_id, product_id, quantity, amount, status, order_date)
              VALUES (?, ?, ?, ?, 'pending', NOW())";

    $stmt = mysqli_prepare($con, $query);

    if (!$stmt) {
        throw new Exception("Failed to create order");
    }

    mysqli_stmt_bind_param(
        $stmt,
        "iiid",
        $user_id,
        $product_id,
        $quantity,
        $amount
    );

    if (!mysqli_stmt_execute($stmt)) {
        mysqli_stmt_close($stmt);
        throw new Exception("Failed to create order");
    }

    $order_id = mysqli_insert_id($con);

    mysqli_stmt_close($stmt);

    /*
    |----------------------------------------------------------------------
    | Reduce Stock
    |----------------------------------------------------------------------
    */

    $query = "UPDATE products
              SET stock = stock - ?
              WHERE id = ?";

    $stmt = mysqli_prepare($con, $query);

    if (!$stmt) {
        throw new Exception("Failed to update stock");
    }

    mysqli_stmt_bind_param(
        $stmt,
        "ii",
        $quantity,
        $product_id
    );

    if (!mysqli_stmt_execute($stmt)) {
        mysqli_stmt_close($stmt);
        throw new Exception("Failed to update stock");
    }

    mysqli_stmt_close($stmt);

    /*
    |----------------------------------------------------------------------
    | Commit Transaction
    |----------------------------------------------------------------------
    */

    mysqli_commit($con);

    echo json_encode([
        "status" => true,
        "message" => "Order placed successfully",
        "order" => [
            "order_id" => $order_id,
            "product_id" => $product_id,
            "product_name" => $product['name'],
            "quantity" => $quantity,
            "price" => $price,
            "amount" => $amount,
            "status" => "pending"
        ]
    ]);

} catch (Throwable $e) {

    mysqli_rollback($con);

    echo json_encode([
        "status" => false,
        "message" => $e->getMessage()
    ]);
}

?>