<?php

declare(strict_types=1);

header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

/*
|--------------------------------------------------------------------------
| Database Connection
|--------------------------------------------------------------------------
*/

$host = getenv('DB_HOST');
$port = (int) getenv('DB_PORT');
$dbname = getenv('DB_NAME');
$username = getenv('DB_USER');
$password = getenv('DB_PASSWORD');

$con = new mysqli(
    $host,
    $username,
    $password,
    $dbname,
    $port
);

if ($con->connect_error) {
    http_response_code(500);

    echo json_encode([
        "success" => false,
        "message" => "Database connection failed",
        "error" => $con->connect_error
    ]);

    exit;
}

$con->set_charset("utf8mb4");


/*
|--------------------------------------------------------------------------
| Helper Functions
|--------------------------------------------------------------------------
*/

function sendResponse(
    bool $success,
    string $message,
    array $data = [],
    int $statusCode = 200
): void {
    http_response_code($statusCode);

    echo json_encode([
        "success" => $success,
        "message" => $message,
        "data" => $data
    ]);

    exit;
}

function getRequestData(): array
{
    $input = file_get_contents("php://input");

    if (!$input) {
        return [];
    }

    $data = json_decode($input, true);

    return is_array($data) ? $data : [];
}


/*
|--------------------------------------------------------------------------
| Request Data
|--------------------------------------------------------------------------
*/

$method = $_SERVER['REQUEST_METHOD'];

$data = getRequestData();

$action = $_GET['action'] ?? ($data['action'] ?? '');


/*
|--------------------------------------------------------------------------
| ADD ADDRESS
|--------------------------------------------------------------------------
*/

if ($action === 'add') {

    $turfId = (int) ($data['turf_id'] ?? 0);
    $address = trim($data['address'] ?? '');
    $city = trim($data['city'] ?? '');
    $district = trim($data['district'] ?? '');
    $state = trim($data['state'] ?? '');
    $pincode = trim($data['pincode'] ?? '');

    $latitude = isset($data['latitude'])
        ? (float) $data['latitude']
        : null;

    $longitude = isset($data['longitude'])
        ? (float) $data['longitude']
        : null;


    if ($turfId <= 0) {
        sendResponse(
            false,
            "Valid turf_id is required",
            [],
            400
        );
    }

    if ($address === '' || $city === '' || $district === '' || $state === '' || $pincode === '') {
        sendResponse(
            false,
            "Address, city, district, state and pincode are required",
            [],
            400
        );
    }


    /*
    | Check whether address already exists
    */

    $check = $con->prepare(
        "SELECT address_id FROM address_tb WHERE turf_id = ? LIMIT 1"
    );

    $check->bind_param("i", $turfId);
    $check->execute();

    $result = $check->get_result();

    if ($result->num_rows > 0) {
        sendResponse(
            false,
            "Address already exists for this turf",
            [],
            409
        );
    }

    $check->close();


    /*
    | Insert address
    */

    $stmt = $con->prepare(
        "INSERT INTO address_tb
        (
            turf_id,
            address,
            city,
            district,
            state,
            pincode,
            latitude,
            longitude
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    );

    $stmt->bind_param(
        "isssssdd",
        $turfId,
        $address,
        $city,
        $district,
        $state,
        $pincode,
        $latitude,
        $longitude
    );

    if (!$stmt->execute()) {

        $error = $stmt->error;
        $stmt->close();

        sendResponse(
            false,
            "Failed to add address",
            ["error" => $error],
            500
        );
    }

    $addressId = $stmt->insert_id;

    $stmt->close();


    sendResponse(
        true,
        "Address added successfully",
        [
            "address_id" => $addressId,
            "turf_id" => $turfId
        ],
        201
    );
}


/*
|--------------------------------------------------------------------------
| GET ADDRESS
|--------------------------------------------------------------------------
*/

if ($action === 'get') {

    $turfId = (int) ($_GET['turf_id'] ?? ($data['turf_id'] ?? 0));

    if ($turfId <= 0) {
        sendResponse(
            false,
            "Valid turf_id is required",
            [],
            400
        );
    }

    $stmt = $con->prepare(
        "SELECT
            address_id,
            turf_id,
            address,
            city,
            district,
            state,
            pincode,
            latitude,
            longitude
        FROM address_tb
        WHERE turf_id = ?
        LIMIT 1"
    );

    $stmt->bind_param("i", $turfId);
    $stmt->execute();

    $result = $stmt->get_result();

    if ($result->num_rows === 0) {

        $stmt->close();

        sendResponse(
            false,
            "Address not found",
            [],
            404
        );
    }

    $address = $result->fetch_assoc();

    $stmt->close();


    sendResponse(
        true,
        "Address fetched successfully",
        $address
    );
}


/*
|--------------------------------------------------------------------------
| UPDATE ADDRESS
|--------------------------------------------------------------------------
*/

if ($action === 'update') {

    $addressId = (int) ($data['address_id'] ?? 0);

    $address = trim($data['address'] ?? '');
    $city = trim($data['city'] ?? '');
    $district = trim($data['district'] ?? '');
    $state = trim($data['state'] ?? '');
    $pincode = trim($data['pincode'] ?? '');

    $latitude = isset($data['latitude'])
        ? (float) $data['latitude']
        : null;

    $longitude = isset($data['longitude'])
        ? (float) $data['longitude']
        : null;


    if ($addressId <= 0) {
        sendResponse(
            false,
            "Valid address_id is required",
            [],
            400
        );
    }

    if ($address === '' || $city === '' || $district === '' || $state === '' || $pincode === '') {
        sendResponse(
            false,
            "Address, city, district, state and pincode are required",
            [],
            400
        );
    }


    $stmt = $con->prepare(
        "UPDATE address_tb
        SET
            address = ?,
            city = ?,
            district = ?,
            state = ?,
            pincode = ?,
            latitude = ?,
            longitude = ?
        WHERE address_id = ?"
    );

    $stmt->bind_param(
        "sssssddi",
        $address,
        $city,
        $district,
        $state,
        $pincode,
        $latitude,
        $longitude,
        $addressId
    );


    if (!$stmt->execute()) {

        $error = $stmt->error;
        $stmt->close();

        sendResponse(
            false,
            "Failed to update address",
            ["error" => $error],
            500
        );
    }

    if ($stmt->affected_rows === 0) {

        $stmt->close();

        sendResponse(
            false,
            "Address not found or no changes made",
            [],
            404
        );
    }

    $stmt->close();


    sendResponse(
        true,
        "Address updated successfully",
        [
            "address_id" => $addressId
        ]
    );
}


/*
|--------------------------------------------------------------------------
| DELETE ADDRESS
|--------------------------------------------------------------------------
*/

if ($action === 'delete') {

    $addressId = (int) ($data['address_id'] ?? 0);

    if ($addressId <= 0) {
        sendResponse(
            false,
            "Valid address_id is required",
            [],
            400
        );
    }


    $stmt = $con->prepare(
        "DELETE FROM address_tb WHERE address_id = ?"
    );

    $stmt->bind_param("i", $addressId);


    if (!$stmt->execute()) {

        $error = $stmt->error;
        $stmt->close();

        sendResponse(
            false,
            "Failed to delete address",
            ["error" => $error],
            500
        );
    }

    if ($stmt->affected_rows === 0) {

        $stmt->close();

        sendResponse(
            false,
            "Address not found",
            [],
            404
        );
    }

    $stmt->close();


    sendResponse(
        true,
        "Address deleted successfully",
        [
            "address_id" => $addressId
        ]
    );
}


/*
|--------------------------------------------------------------------------
| Invalid Action
|--------------------------------------------------------------------------
*/

sendResponse(
    false,
    "Invalid or missing action. Use add, get, update or delete.",
    [],
    400
);