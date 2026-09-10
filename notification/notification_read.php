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

    if (
        !isset($decoded->data->id) ||
        !isset($decoded->data->role)
    ) {
        echo json_encode([
            "status" => false,
            "message" => "Invalid token"
        ]);
        exit;
    }

    $user_id = (int)$decoded->data->id;
    $role = $decoded->data->role;

    if ($role !== 'user') {
        echo json_encode([
            "status" => false,
            "message" => "Only users can update notifications"
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
| Get Notification ID
|--------------------------------------------------------------------------
*/

$notification_id = $_POST['notification_id'] ?? '';

if (
    $notification_id === '' ||
    !is_numeric($notification_id)
) {
    echo json_encode([
        "status" => false,
        "message" => "Valid notification ID is required"
    ]);
    exit;
}

$notification_id = (int)$notification_id;

/*
|--------------------------------------------------------------------------
| Check Notification Ownership
|--------------------------------------------------------------------------
*/

$query = "SELECT id
          FROM notifications
          WHERE id = ?
          AND user_id = ?
          LIMIT 1";

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
    "ii",
    $notification_id,
    $user_id
);

mysqli_stmt_execute($stmt);

$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) === 0) {

    echo json_encode([
        "status" => false,
        "message" => "Notification not found"
    ]);

    mysqli_stmt_close($stmt);
    exit;
}

mysqli_stmt_close($stmt);

/*
|--------------------------------------------------------------------------
| Mark Notification As Read
|--------------------------------------------------------------------------
*/

$query = "UPDATE notifications
          SET is_read = 1
          WHERE id = ?
          AND user_id = ?";

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
    "ii",
    $notification_id,
    $user_id
);

if (mysqli_stmt_execute($stmt)) {

    echo json_encode([
        "status" => true,
        "message" => "Notification marked as read"
    ]);

} else {

    echo json_encode([
        "status" => false,
        "message" => "Failed to update notification"
    ]);
}

mysqli_stmt_close($stmt);

?>