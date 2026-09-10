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

    if (!isset($decoded->data->role)) {
        echo json_encode([
            "status" => false,
            "message" => "Invalid token"
        ]);
        exit;
    }

    $role = $decoded->data->role;

    if ($role !== 'owner' && $role !== 'admin') {
        echo json_encode([
            "status" => false,
            "message" => "Access denied"
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
| Get Product ID
|--------------------------------------------------------------------------
*/

$product_id = $_POST['product_id'] ?? '';

if ($product_id === '' || !is_numeric($product_id)) {

    echo json_encode([
        "status" => false,
        "message" => "Valid product ID is required"
    ]);

    exit;
}

$product_id = (int)$product_id;

/*
|--------------------------------------------------------------------------
| Check Product
|--------------------------------------------------------------------------
*/

$query = "SELECT id, status
          FROM products
          WHERE id = ?
          LIMIT 1";

$stmt = mysqli_prepare($con, $query);

if (!$stmt) {

    echo json_encode([
        "status" => false,
        "message" => "Database query failed"
    ]);

    exit;
}

mysqli_stmt_bind_param($stmt, "i", $product_id);
mysqli_stmt_execute($stmt);

$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) === 0) {

    echo json_encode([
        "status" => false,
        "message" => "Product not found"
    ]);

    mysqli_stmt_close($stmt);
    exit;
}

$product = mysqli_fetch_assoc($result);

mysqli_stmt_close($stmt);

/*
|--------------------------------------------------------------------------
| Check Already Deleted
|--------------------------------------------------------------------------
*/

if ($product['status'] === 'inactive') {

    echo json_encode([
        "status" => false,
        "message" => "Product is already inactive"
    ]);

    exit;
}

/*
|--------------------------------------------------------------------------
| Soft Delete Product
|--------------------------------------------------------------------------
*/

$query = "UPDATE products
          SET status = 'inactive'
          WHERE id = ?";

$stmt = mysqli_prepare($con, $query);

if (!$stmt) {

    echo json_encode([
        "status" => false,
        "message" => "Database query failed"
    ]);

    exit;
}

mysqli_stmt_bind_param($stmt, "i", $product_id);

if (mysqli_stmt_execute($stmt)) {

    echo json_encode([
        "status" => true,
        "message" => "Product deleted successfully"
    ]);

} else {

    echo json_encode([
        "status" => false,
        "message" => "Failed to delete product"
    ]);
}

mysqli_stmt_close($stmt);

?>