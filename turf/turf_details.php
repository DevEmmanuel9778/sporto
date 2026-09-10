<?php

header("Content-Type: application/json");

require_once "../connection.php";

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    echo json_encode([
        "status" => false,
        "message" => "Only GET method is allowed"
    ]);
    exit;
}

$turfId = (int)($_GET['id'] ?? 0);

if ($turfId <= 0) {
    echo json_encode([
        "status" => false,
        "message" => "Valid turf ID is required"
    ]);
    exit;
}

$stmt = $con->prepare(
    "SELECT
        t.id,
        t.owner_id,
        t.name,
        t.turf_type,
        t.description,
        t.location,
        t.contact,
        t.price,
        t.status,
        o.name AS owner_name,
        o.phone AS owner_phone
     FROM turfs t
     INNER JOIN turf_owners o
        ON t.owner_id = o.id
     WHERE t.id = ?
     AND t.status = 'active'
     LIMIT 1"
);

$stmt->bind_param("i", $turfId);
$stmt->execute();

$result = $stmt->get_result();

if ($result->num_rows === 0) {

    echo json_encode([
        "status" => false,
        "message" => "Turf not found"
    ]);

    exit;
}

$turf = $result->fetch_assoc();

$imageStmt = $con->prepare(
    "SELECT
        id,
        image,
        is_primary
     FROM turf_image_tb
     WHERE turf_id = ?
     ORDER BY is_primary DESC, id DESC"
);

$imageStmt->bind_param("i", $turfId);
$imageStmt->execute();

$imageResult = $imageStmt->get_result();

$images = [];

while ($image = $imageResult->fetch_assoc()) {

    $images[] = [
        "id" => (int)$image['id'],
        "image" => $image['image'],
        "is_primary" => (int)$image['is_primary']
    ];
}

echo json_encode([
    "status" => true,
    "message" => "Turf details fetched successfully",
    "turf" => [
        "id" => (int)$turf['id'],
        "owner_id" => (int)$turf['owner_id'],
        "name" => $turf['name'],
        "turf_type" => $turf['turf_type'],
        "description" => $turf['description'],
        "location" => $turf['location'],
        "contact" => $turf['contact'],
        "price" => (float)$turf['price'],
        "status" => $turf['status'],
        "owner_name" => $turf['owner_name'],
        "owner_phone" => $turf['owner_phone'],
        "images" => $images
    ]
]);

$stmt->close();
$imageStmt->close();
$con->close();

?>