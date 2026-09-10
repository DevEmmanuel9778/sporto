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
| Get Form Data
|--------------------------------------------------------------------------
*/

$name = trim($_POST['name'] ?? '');
$category = trim($_POST['category'] ?? '');
$price = $_POST['price'] ?? '';
$stock = $_POST['stock'] ?? '';
$image = trim($_POST['image'] ?? '');

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

/*
|--------------------------------------------------------------------------
| Insert Product
|--------------------------------------------------------------------------
*/

$query = "INSERT INTO products
          (name, category, price, stock, image, status)
          VALUES (?, ?, ?, ?, ?, 'active')";

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
    "ssd is",
    $name,
    $category,
    $price,
    $stock,
    $image
);