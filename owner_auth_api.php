<?php

declare(strict_types=1);

header("Content-Type: application/json; charset=UTF-8");

require_once __DIR__ . "/vendor/autoload.php";

use Firebase\JWT\JWT;


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

function sendResponse(
    bool $status,
    string $message,
    array $data = [],
    int $httpCode = 200
): never {

    http_response_code($httpCode);

    echo json_encode(
        array_merge(
            [
                "status" => $status,
                "message" => $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE
    );

    exit;
}


/*
|--------------------------------------------------------------------------
| REQUEST
|--------------------------------------------------------------------------
*/

$input = file_get_contents("php://input");

$data = [];

if ($input !== false && trim($input) !== "") {

    $data = json_decode(
        $input,
        true
    );

    if (!is_array($data)) {

        sendResponse(
            false,
            "Invalid JSON request",
            [],
            400
        );
    }
}


$action = strtolower(
    trim($data["action"] ?? "")
);


/*
|--------------------------------------------------------------------------
| ENVIRONMENT
|--------------------------------------------------------------------------
*/

$host = getenv("DB_HOST");
$port = (int) getenv("DB_PORT");
$dbname = getenv("DB_NAME");
$username = getenv("DB_USER");
$password = getenv("DB_PASSWORD");

$secretKey = getenv("JWT_SECRET");


if (
    $host === false ||
    trim($host) === "" ||
    $port <= 0 ||
    $dbname === false ||
    trim($dbname) === "" ||
    $username === false ||
    trim($username) === "" ||
    $password === false
) {

    sendResponse(
        false,
        "Database environment variables are missing or invalid",
        [],
        500
    );
}


if (
    $secretKey === false ||
    trim($secretKey) === ""
) {

    sendResponse(
        false,
        "JWT_SECRET environment variable is missing",
        [],
        500
    );
}


/*
|--------------------------------------------------------------------------
| AIVEN SSL CONNECTION
|--------------------------------------------------------------------------
*/

try {

    $con = mysqli_init();

    if ($con === false) {

        throw new RuntimeException(
            "Failed to initialize MySQL connection"
        );
    }


    mysqli_ssl_set(
        $con,
        null,
        null,
        null,
        null,
        null
    );


    if (!mysqli_real_connect(
        $con,
        $host,
        $username,
        $password,
        $dbname,
        $port,
        null,
        MYSQLI_CLIENT_SSL
    )) {

        throw new RuntimeException(
            mysqli_connect_error() ?: "Unknown database connection error"
        );
    }

} catch (Throwable $e) {

    sendResponse(
        false,
        "Database connection failed",
        [
            "error" => $e->getMessage()
        ],
        500
    );
}


$con->set_charset("utf8mb4");


/*
|--------------------------------------------------------------------------
| ONLY LOGIN
|--------------------------------------------------------------------------
*/

if ($action !== "login") {

    sendResponse(
        false,
        "Invalid action. Use login",
        [],
        400
    );
}


/*
|--------------------------------------------------------------------------
| OWNER LOGIN DATA
|--------------------------------------------------------------------------
*/

$ownerUsername = trim(
    $data["username"] ??
    $data["email"] ??
    ""
);

$loginPassword = $data["password"] ?? "";


if (
    $ownerUsername === "" ||
    $loginPassword === ""
) {

    sendResponse(
        false,
        "Username and password are required",
        [],
        400
    );
}


/*
|--------------------------------------------------------------------------
| FIND OWNER
|--------------------------------------------------------------------------
*/

$stmt = $con->prepare(
    "SELECT
        id,
        username,
        password
     FROM ownerreg_tb
     WHERE username = ?
     LIMIT 1"
);


if (!$stmt) {

    sendResponse(
        false,
        "Database query failed",
        [],
        500
    );
}


$stmt->bind_param(
    "s",
    $ownerUsername
);


if (!$stmt->execute()) {

    $error = $stmt->error;

    $stmt->close();

    sendResponse(
        false,
        "Login query failed",
        [
            "error" => $error
        ],
        500
    );
}


$result = $stmt->get_result();


if ($result->num_rows === 0) {

    $stmt->close();

    sendResponse(
        false,
        "Invalid username or password",
        [],
        401
    );
}


$owner = $result->fetch_assoc();

$stmt->close();


/*
|--------------------------------------------------------------------------
| PASSWORD CHECK
|--------------------------------------------------------------------------
*/

if (!password_verify(
    $loginPassword,
    $owner["password"]
)) {

    sendResponse(
        false,
        "Invalid username or password",
        [],
        401
    );
}


$ownerId = (int) $owner["id"];

$name = (string) $owner["username"];


/*
|--------------------------------------------------------------------------
| JWT
|--------------------------------------------------------------------------
*/

$issuedAt = time();

$accessToken = JWT::encode(
    [
        "iss" => "sporto-api",
        "iat" => $issuedAt,
        "exp" => $issuedAt + 900,
        "user_id" => $ownerId,
        "name" => $name,
        "email" => $name,
        "role" => "owner",
        "type" => "access"
    ],
    $secretKey,
    "HS256"
);


/*
|--------------------------------------------------------------------------
| SAVE ACCESS TOKEN
|--------------------------------------------------------------------------
*/

$updateStmt = $con->prepare(
    "UPDATE ownerreg_tb
     SET token = ?
     WHERE id = ?"
);


if (!$updateStmt) {

    sendResponse(
        false,
        "Failed to prepare token update",
        [],
        500
    );
}


$updateStmt->bind_param(
    "si",
    $accessToken,
    $ownerId
);


if (!$updateStmt->execute()) {

    $error = $updateStmt->error;

    $updateStmt->close();

    sendResponse(
        false,
        "Failed to save token",
        [
            "error" => $error
        ],
        500
    );
}


$updateStmt->close();


/*
|--------------------------------------------------------------------------
| SUCCESS
|--------------------------------------------------------------------------
*/

sendResponse(
    true,
    "Owner login successful",
    [
        "user_id" => $ownerId,
        "name" => $name,
        "email" => $name,
        "role" => "owner",
        "access_token" => $accessToken
    ]
);