<?php

header("Content-Type: application/json");
include '../connection.php';

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    echo json_encode([
        "status" => false,
        "message" => "Only GET method is allowed"
    ]);
    exit;
}

if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    echo json_encode([
        "status" => false,
        "message" => "Product ID is required"
    ]);
    exit;
}

$id = (int)$_GET['id'];

$query = "SELECT id, name, category, price, stock, image, status
          FROM products
          WHERE id = ? AND status = 'active'
          LIMIT 1";

$stmt = mysqli_prepare($con, $query);

if (!$stmt) {
    echo json_encode([
        "status" => false,
        "message" => "Database query failed"
    ]);
    exit;
}

mysqli_stmt_bind_param($stmt, "i", $id);
mysqli_stmt_execute($stmt);

$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) === 0) {
    echo json_encode([
        "status" => false,
        "message" => "Product not found"
    ]);
    exit;
}

$product = mysqli_fetch_assoc($result);

$product['id'] = (int)$product['id'];
$product['price'] = (float)$product['price'];
$product['stock'] = (int)$product['stock'];

echo json_encode([
    "status" => true,
    "message" => "Product details fetched successfully",
    "product" => $product
]);

mysqli_stmt_close($stmt);

?>