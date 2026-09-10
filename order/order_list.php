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
            "message" => "Only users can view orders"
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
| Get Orders
|--------------------------------------------------------------------------
*/

$query = "SELECT
            o.id,
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
          WHERE o.user_id = ?
          ORDER BY o.id DESC";

$stmt = mysqli_prepare($con, $query);

if (!$stmt) {
    echo json_encode([
        "status" => false,
        "message" => "Database query failed"
    ]);
    exit;
}

mysqli_stmt_bind_param($stmt, "i", $user_id);
mysqli_stmt_execute($stmt);

$result = mysqli_stmt_get_result($stmt);

$orders = [];

while ($row = mysqli_fetch_assoc($result)) {

    $row['id'] = (int)$row['id'];
    $row['product_id'] = (int)$row['product_id'];
    $row['price'] = (float)$row['price'];
    $row['quantity'] = (int)$row['quantity'];
    $row['amount'] = (float)$row['amount'];

    $orders[] = $row;
}

echo json_encode([
    "status" => true,
    "message" => "Orders fetched successfully",
    "orders" => $orders
]);

mysqli_stmt_close($stmt);

?>