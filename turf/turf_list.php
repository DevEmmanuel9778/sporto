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
        ti.image
     FROM turfs t
     LEFT JOIN turf_image_tb ti
        ON t.id = ti.turf_id
        AND ti.is_primary = 1
     WHERE t.status = 'active'
     ORDER BY t.id DESC"
);

$stmt->execute();

$result = $stmt->get_result();

$turfs = [];

while ($row = $result->fetch_assoc()) {

    $turfs[] = [
        "id" => (int)$row['id'],
        "owner_id" => (int)$row['owner_id'],
        "name" => $row['name'],
        "turf_type" => $row['turf_type'],
        "description" => $row['description'],
        "location" => $row['location'],
        "contact" => $row['contact'],
        "price" => (float)$row['price'],
        "status" => $row['status'],
        "image" => $row['image']
    ];
}

echo json_encode([
    "status" => true,
    "message" => "Turfs fetched successfully",
    "turfs" => $turfs
]);

$stmt->close();
$con->close();

?>