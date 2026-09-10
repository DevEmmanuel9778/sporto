<?php

header("Content-Type: application/json");

require_once '../connection.php';
require_once '../config/jwt.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    echo json_encode([
        "status" => false,
        "message" => "Only GET method is allowed"
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
            "message" => "Only users can view order details"
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

if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {

    echo json_encode([
        "status" => false,
        "message" => "Valid order ID is required"
    ]);

    exit;
}

$order_id = (int)$_GET['id'];

/*
|--------------------------------------------------------------------------
| Get Order Details
|--------------------------------------------------------------------------
*/

$query = "SELECT
            o.id,
            o.user_id,
            o.product_id,
            p.name AS product_name,
            p.category,
            p.image,
            p.price,
            o.quantity,
            o.amount,
            o.status,
            o.order_date
          FROM orders o
          INNER JOIN products p
          ON o.product_id = p.id
          WHERE o.id = ?
          AND o.user_id = ?
          LIMIT 1";

$stmt = mysqli_prepare($con, $query);

if (!$stmt) {

    echo json_encode([
        "status" => false,
        "message" => "Database query failed"
    ]);

    exit;
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

    echo json_encode([
        "status" => false,
        "message" => "Order not found"
    ]);

    mysqli_stmt_close($stmt);
    exit;
}

$order = mysqli_fetch_assoc($result);

$order['id'] = (int)$order['id'];
$order['user_id'] = (int)$order['user_id'];
$order['product_id'] = (int)$order['product_id'];
$order['price'] = (float)$order['price'];
$order['quantity'] = (int)$order['quantity'];
$order['amount'] = (float)$order['amount'];

echo json_encode([
    "status" => true,
    "message" => "Order details fetched successfully",
    "order" => $order
]);

mysqli_stmt_close($stmt);

?>