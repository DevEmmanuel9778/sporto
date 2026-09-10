<?php

header("Content-Type: application/json");

require_once "../connection.php";
require_once "../config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode([
        "status" => false,
        "message" => "Only POST method is allowed"
    ]);
    exit;
}

$headers = getallheaders();
$authHeader = $headers['Authorization'] ?? '';

if ($authHeader === '') {
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

$accessToken = $matches[1];

try {

    $decoded = JWT::decode(
        $accessToken,
        new Key($secret_key, "HS256")
    );

} catch (Throwable $e) {

    echo json_encode([
        "status" => false,
        "message" => "Invalid or expired access token"
    ]);
    exit;
}

$ownerId = $decoded->user_id ?? null;
$role = $decoded->role ?? null;

if (!$ownerId || $role !== "owner") {
    echo json_encode([
        "status" => false,
        "message" => "Only turf owners can upload images"
    ]);
    exit;
}

$turfId = (int)($_POST['turf_id'] ?? 0);
$isPrimary = (int)($_POST['is_primary'] ?? 0);

if ($turfId <= 0) {
    echo json_encode([
        "status" => false,
        "message" => "Valid turf ID is required"
    ]);
    exit;
}

if (!isset($_FILES['image'])) {
    echo json_encode([
        "status" => false,
        "message" => "Image file is required"
    ]);
    exit;
}

if ($_FILES['image']['error'] !== UPLOAD_ERR_OK) {
    echo json_encode([
        "status" => false,
        "message" => "Image upload failed"
    ]);
    exit;
}

/*
 * Check whether turf belongs to this owner.
 */
$checkStmt = $con->prepare(
    "SELECT id
     FROM turfs
     WHERE id = ?
     AND owner_id = ?
     LIMIT 1"
);

$checkStmt->bind_param(
    "ii",
    $turfId,
    $ownerId
);

$checkStmt->execute();

$checkResult = $checkStmt->get_result();

if ($checkResult->num_rows === 0) {

    echo json_encode([
        "status" => false,
        "message" => "Turf not found or unauthorized"
    ]);

    exit;
}

$checkStmt->close();

$file = $_FILES['image'];

$allowedTypes = [
    'image/jpeg',
    'image/png',
    'image/webp'
];

$fileType = mime_content_type($file['tmp_name']);

if (!in_array($fileType, $allowedTypes, true)) {
    echo json_encode([
        "status" => false,
        "message" => "Only JPG, PNG and WEBP images are allowed"
    ]);
    exit;
}

$maxSize = 5 * 1024 * 1024;

if ($file['size'] > $maxSize) {
    echo json_encode([
        "status" => false,
        "message" => "Image size must be less than 5 MB"
    ]);
    exit;
}

$uploadDirectory = "../uploads/turfs/";

if (!is_dir($uploadDirectory)) {
    mkdir($uploadDirectory, 0777, true);
}

$extension = strtolower(
    pathinfo($file['name'], PATHINFO_EXTENSION)
);

$fileName = uniqid(
    "turf_",
    true
) . "." . $extension;

$filePath = $uploadDirectory . $fileName;

if (!move_uploaded_file(
    $file['tmp_name'],
    $filePath
)) {

    echo json_encode([
        "status" => false,
        "message" => "Failed to save image"
    ]);

    exit;
}

/*
 * If this image is primary,
 * remove primary status from existing images.
 */
if ($isPrimary === 1) {

    $resetStmt = $con->prepare(
        "UPDATE turf_image_tb
         SET is_primary = 0
         WHERE turf_id = ?"
    );

    $resetStmt->bind_param(
        "i",
        $turfId
    );

    $resetStmt->execute();
    $resetStmt->close();
}

$imageUrl = "uploads/turfs/" . $fileName;

$stmt = $con->prepare(
    "INSERT INTO turf_image_tb
    (
        turf_id,
        image,
        is_primary
    )
    VALUES (?, ?, ?)"
);

$stmt->bind_param(
    "isi",
    $turfId,
    $imageUrl,
    $isPrimary
);

if ($stmt->execute()) {

    echo json_encode([
        "status" => true,
        "message" => "Turf image uploaded successfully",
        "image_id" => $stmt->insert_id,
        "image" => $imageUrl
    ]);

} else {

    unlink($filePath);

    echo json_encode([
        "status" => false,
        "message" => "Failed to save image details"
    ]);
}

$stmt->close();
$con->close();

?>