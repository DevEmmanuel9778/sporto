<?php

header("Content-Type: application/json");

require_once "../connection.php";

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode([
        "status" => false,
        "message" => "Only POST method is allowed"
    ]);
    exit;
}

$data = json_decode(file_get_contents("php://input"), true);

$refreshToken = $data['refresh_token'] ?? '';

if ($refreshToken === '') {
    echo json_encode([
        "status" => false,
        "message" => "Refresh token is required"
    ]);
    exit;
}

$tokenHash = hash('sha256', $refreshToken);

$stmt = $con->prepare(
    "UPDATE refresh_tokens
     SET revoked = 1
     WHERE token_hash = ?"
);

$stmt->bind_param("s", $tokenHash);

if ($stmt->execute()) {

    echo json_encode([
        "status" => true,
        "message" => "Logged out successfully"
    ]);

} else {

    echo json_encode([
        "status" => false,
        "message" => "Logout failed"
    ]);
}

$stmt->close();
$con->close();

?>


── user/
│   ├── profile.php
│   ├── address_add.php
│   ├── address_list.php
│   ├── address_update.php
│   └── address_delete.php
│
├── turf/
│   ├── turf_list.php
│   ├── turf_details.php
│   ├── turf_add.php
│   ├── turf_update.php
│   ├── turf_delete.php
│   ├── turf_image_add.php
│   └── turf_slots.php
│
├── booking/
│   ├── booking_create.php
│   ├── booking_list.php
│   ├── booking_details.php
│   └── booking_cancel.php
│
├── payment/
│   └── payment_create.php
│
├── product/
│   ├── product_list.php
│   ├── product_details.php
│   ├── product_add.php
│   ├── product_update.php
│   └── product_delete.php
│
├── order/
│   ├── order_create.php
│   ├── order_list.php
│   ├── order_details.php
│   └── order_ca

├── notification/
│   ├── notification_list.php
│   └── notification_read.php
│
└── uploads/
    ├── turfs/
    └── products/