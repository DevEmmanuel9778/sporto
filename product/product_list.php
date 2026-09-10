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

$query = "SELECT id, name, category, price, stock, image, status
          FROM products
          WHERE status = 'active'
          ORDER BY id DESC";

$result = mysqli_query($con, $query);

if (!$result) {
    echo json_encode([
        "status" => false,
        "message" => "Failed to fetch products"
    ]);
    exit;
}

$products = [];

while ($row = mysqli_fetch_assoc($result)) {

    $row['id'] = (int)$row['id'];
    $row['price'] = (float)$row['price'];
    $row['stock'] = (int)$row['stock'];

    $products[] = $row;
}

echo json_encode([
    "status" => true,
    "message" => "Products fetched successfully",
    "products" => $products
]);

?>
