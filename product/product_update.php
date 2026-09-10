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

$query = "SELECT id FROM products WHERE id = ? LIMIT 1";

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

mysqli_stmt_close($stmt);

/*
|--------------------------------------------------------------------------
| Get Update Data
|--------------------------------------------------------------------------
*/

$name = trim($_POST['name'] ?? '');
$category = trim($_POST['category'] ?? '');
$price = $_POST['price'] ?? '';
$stock = $_POST['stock'] ?? '';
$image = trim($_POST['image'] ?? '');
$status = trim($_POST['status'] ?? '');

/*
|--------------------------------------------------------------------------
| Validation
|--------------------------------------------------------------------------
*/

if ($name === '' || $category === '' || $price === '' || $stock === '') {

    echo json_encode([
        "status" => false,
        "message" => "Name, category, price and stock are required"
    ]);

    exit;
}

if (!is_numeric($price) || $price < 0) {

    echo json_encode([
        "status" => false,
        "message" => "Invalid price"
    ]);

    exit;
}

if (!is_numeric($stock) || $stock < 0 || floor($stock) != $stock) {

    echo json_encode([
        "status" => false,
        "message" => "Invalid stock value"
    ]);

    exit;
}

$price = (float)$price;
$stock = (int)$stock;

if ($status === '') {
    $status = 'active';
}

$allowed_status = ['active', 'inactive'];

if (!in_array($status, $allowed_status, true)) {

    echo json_encode([
        "status" => false,
        "message" => "Invalid product status"
    ]);

    exit;
}

/*
|--------------------------------------------------------------------------
| Update Product
|--------------------------------------------------------------------------
*/

$query = "UPDATE products
          SET name = ?,
              category = ?,
              price = ?,
              stock = ?,
              image = ?,
              status = ?
          WHERE id = ?";

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
    "ssdis si",
    $name,
    $category,
    $price,
    $stock,
    $image,
    $status,
    $product_id
);