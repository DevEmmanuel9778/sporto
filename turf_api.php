<?php

declare(strict_types=1);

header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET");

require_once __DIR__ . "/connection.php";


/*
|--------------------------------------------------------------------------
| METHOD CHECK
|--------------------------------------------------------------------------
*/

if ($_SERVER["REQUEST_METHOD"] !== "GET") {

    http_response_code(405);

    echo json_encode([
        "status" => false,
        "message" => "Only GET method is allowed"
    ]);

    exit;
}


/*
|--------------------------------------------------------------------------
| GET ACTIVE TURFS
|--------------------------------------------------------------------------
*/

$stmt = $con->prepare(
    "SELECT
        turf_id,
        owner_id,
        name,
        turf_type,
        description,
        location,
        contact,
        price,
        status,
        turf_image_url
     FROM turf_tb
     WHERE status = 'active'
     ORDER BY turf_id DESC"
);


if (!$stmt) {

    http_response_code(500);

    echo json_encode([
        "status" => false,
        "message" => "Failed to prepare turf query",
        "error" => $con->error
    ]);

    exit;
}


if (!$stmt->execute()) {

    http_response_code(500);

    echo json_encode([
        "status" => false,
        "message" => "Failed to fetch turfs",
        "error" => $stmt->error
    ]);

    $stmt->close();
    $con->close();

    exit;
}


$result = $stmt->get_result();

$turfs = [];


/*
|--------------------------------------------------------------------------
| BUILD TURF RESPONSE
|--------------------------------------------------------------------------
*/

while ($row = $result->fetch_assoc()) {

    $turfs[] = [

        "id" => (int) $row["turf_id"],

        "owner_id" => (int) $row["owner_id"],

        "name" => $row["name"],

        "turf_type" => $row["turf_type"],

        "description" => $row["description"],

        "location" => $row["location"],

        "contact" => $row["contact"],

        "price" => (float) $row["price"],

        "status" => $row["status"],

        "image" => $row["turf_image_url"]
    ];
}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

echo json_encode(
    [
        "status" => true,
        "message" => "Turfs fetched successfully",
        "turfs" => $turfs
    ],
    JSON_UNESCAPED_UNICODE
);


$stmt->close();

$con->close();

?>