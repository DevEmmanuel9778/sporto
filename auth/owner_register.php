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

$data = json_decode(
    file_get_contents("php://input"),
    true
);

if (!is_array($data)) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid JSON request"
    ]);
    exit;
}

$name = trim($data['name'] ?? '');
$email = trim($data['email'] ?? '');
$phone = trim($data['phone'] ?? '');
$password = $data['password'] ?? '';

/*
|--------------------------------------------------------------------------
| VALIDATION
|--------------------------------------------------------------------------
*/

if (
    $name === '' ||
    $email === '' ||
    $phone === '' ||
    $password === ''
) {
    echo json_encode([
        "status" => false,
        "message" => "All fields are required"
    ]);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode([
        "status" => false,
        "message" => "Invalid email address"
    ]);
    exit;
}

if (strlen($password) < 6) {
    echo json_encode([
        "status" => false,
        "message" => "Password must contain at least 6 characters"
    ]);
    exit;
}

/*
|--------------------------------------------------------------------------
| CHECK EXISTING EMAIL
|--------------------------------------------------------------------------
*/

$check = $con->prepare(
    "SELECT user_id
     FROM userreg_tb
     WHERE email = ?
     LIMIT 1"
);

if (!$check) {
    echo json_encode([
        "status" => false,
        "message" => "Database query preparation failed",
        "error_detail" => $con->error
    ]);
    exit;
}

$check->bind_param(
    "s",
    $email
);

$check->execute();

$result = $check->get_result();

if ($result->num_rows > 0) {

    echo json_encode([
        "status" => false,
        "message" => "Email already registered"
    ]);

    $check->close();
    $con->close();
    exit;
}

$check->close();

/*
|--------------------------------------------------------------------------
| HASH PASSWORD
|--------------------------------------------------------------------------
*/

$hashedPassword = password_hash(
    $password,
    PASSWORD_DEFAULT
);

/*
|--------------------------------------------------------------------------
| INITIAL TOKEN VALUES
|--------------------------------------------------------------------------
|
| Tokens will normally be generated during login.
| Your database columns are NOT NULL, so we store
| empty strings during registration.
|
*/

$token = "";
$refreshToken = "";

/*
|--------------------------------------------------------------------------
| INSERT USER
|--------------------------------------------------------------------------
*/

$stmt = $con->prepare(
    "INSERT INTO userreg_tb
    (
        name,
        email,
        phone,
        password,
        token,
        refresh_token
    )
    VALUES (?, ?, ?, ?, ?, ?)"
);

if (!$stmt) {
    echo json_encode([
        "status" => false,
        "message" => "Database query preparation failed",
        "error_detail" => $con->error
    ]);
    $con->close();
    exit;
}

$stmt->bind_param(
    "ssssss",
    $name,
    $email,
    $phone,
    $hashedPassword,
    $token,
    $refreshToken
);

if ($stmt->execute()) {

    $userId = $stmt->insert_id;

    echo json_encode([
        "status" => true,
        "message" => "success",
        "user" => [
            "user_id" => $userId,
            "name" => $name,
            "email" => $email,
            "phone" => $phone
        ]
    ]);

} else {

    echo json_encode([
        "status" => false,
        "message" => "Registration failed",
        "error_detail" => $stmt->error
    ]);
}

$stmt->close();
$con->close();

?>