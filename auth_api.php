<?php

declare(strict_types=1);

header("Content-Type: application/json; charset=UTF-8");

require_once __DIR__ . "/vendor/autoload.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/*
|--------------------------------------------------------------------------
| COMMON RESPONSE FUNCTION
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
| REQUEST DATA
|--------------------------------------------------------------------------
*/

function getRequestData(): array
{
    $input = file_get_contents("php://input");

    if ($input === false || trim($input) === "") {
        return [];
    }

    $data = json_decode($input, true);

    if (!is_array($data)) {
        sendResponse(
            false,
            "Invalid JSON request",
            [],
            400
        );
    }

    return $data;
}


/*
|--------------------------------------------------------------------------
| DATABASE ENVIRONMENT VARIABLES
|--------------------------------------------------------------------------
*/

$host = getenv("DB_HOST");
$port = (int) getenv("DB_PORT");
$dbname = getenv("DB_NAME");
$username = getenv("DB_USER");
$password = getenv("DB_PASSWORD");


/*
|--------------------------------------------------------------------------
| JWT ENVIRONMENT VARIABLE
|--------------------------------------------------------------------------
*/

$secretKey = getenv("JWT_SECRET");

$issuer = "sporto-api";

$accessTokenExpiry = 900;       // 15 minutes
$refreshTokenExpiry = 2592000;  // 30 days


/*
|--------------------------------------------------------------------------
| CHECK ENVIRONMENT VARIABLES
|--------------------------------------------------------------------------
*/

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
| DATABASE CONNECTION
|--------------------------------------------------------------------------
*/

try {

    $con = new mysqli(
        $host,
        $username,
        $password,
        $dbname,
        $port
    );

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


if ($con->connect_error) {

    sendResponse(
        false,
        "Database connection failed",
        [
            "error" => $con->connect_error
        ],
        500
    );
}


$con->set_charset("utf8mb4");


/*
|--------------------------------------------------------------------------
| GENERATE ACCESS TOKEN
|--------------------------------------------------------------------------
*/

function generateAccessToken(
    string $secretKey,
    string $issuer,
    int $expiry,
    int $userId,
    string $name,
    string $email,
    string $role
): string {

    $issuedAt = time();

    $payload = [
        "iss" => $issuer,
        "iat" => $issuedAt,
        "exp" => $issuedAt + $expiry,
        "user_id" => $userId,
        "name" => $name,
        "email" => $email,
        "role" => $role,
        "type" => "access"
    ];

    return JWT::encode(
        $payload,
        $secretKey,
        "HS256"
    );
}


/*
|--------------------------------------------------------------------------
| GENERATE REFRESH TOKEN
|--------------------------------------------------------------------------
*/

function generateRefreshToken(
    string $secretKey,
    string $issuer,
    int $expiry,
    int $userId,
    string $email,
    string $role
): string {

    $issuedAt = time();

    $payload = [
        "iss" => $issuer,
        "iat" => $issuedAt,
        "exp" => $issuedAt + $expiry,
        "user_id" => $userId,
        "email" => $email,
        "role" => $role,
        "type" => "refresh"
    ];

    return JWT::encode(
        $payload,
        $secretKey,
        "HS256"
    );
}


/*
|--------------------------------------------------------------------------
| SAVE REFRESH TOKEN HASH
|--------------------------------------------------------------------------
*/

function saveRefreshToken(
    mysqli $con,
    int $userId,
    string $role,
    string $refreshToken,
    int $expiry
): void {

    $tokenHash = hash(
        "sha256",
        $refreshToken
    );

    $expiresAt = date(
        "Y-m-d H:i:s",
        time() + $expiry
    );

    $userType = match ($role) {

        "user" => 1,
        "owner" => 2,
        "admin" => 3,
        default => 0
    };


    $stmt = $con->prepare(
        "INSERT INTO refresh_tokens
        (
            user_type,
            user_id,
            token_hash,
            expires_at,
            revoked
        )
        VALUES (?, ?, ?, ?, 0)"
    );


    if (!$stmt) {

        sendResponse(
            false,
            "Failed to prepare refresh token query",
            [],
            500
        );
    }


    $stmt->bind_param(
        "iiss",
        $userType,
        $userId,
        $tokenHash,
        $expiresAt
    );


    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        sendResponse(
            false,
            "Failed to save refresh token",
            [
                "error" => $error
            ],
            500
        );
    }


    $stmt->close();
}


/*
|--------------------------------------------------------------------------
| REQUEST
|--------------------------------------------------------------------------
*/

$data = getRequestData();

$action = strtolower(
    trim($data["action"] ?? "")
);


/*
|--------------------------------------------------------------------------
| REGISTER USER
|--------------------------------------------------------------------------
*/

if ($action === "register") {

    $name = trim(
        $data["name"] ?? ""
    );

    $email = strtolower(
        trim($data["email"] ?? "")
    );

    $phone = trim(
        $data["phone"] ?? ""
    );

    $registerPassword = $data["password"] ?? "";


    if (
        $name === "" ||
        $email === "" ||
        $phone === "" ||
        $registerPassword === ""
    ) {

        sendResponse(
            false,
            "Name, email, phone and password are required",
            [],
            400
        );
    }


    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        sendResponse(
            false,
            "Invalid email address",
            [],
            400
        );
    }


    if (strlen($registerPassword) < 6) {

        sendResponse(
            false,
            "Password must contain at least 6 characters",
            [],
            400
        );
    }


    /*
    |--------------------------------------------------------------------------
    | CHECK EXISTING USER
    |--------------------------------------------------------------------------
    */

    $checkStmt = $con->prepare(
        "SELECT user_id
         FROM userreg_tb
         WHERE email = ?
         LIMIT 1"
    );


    if (!$checkStmt) {

        sendResponse(
            false,
            "Database query failed",
            [],
            500
        );
    }


    $checkStmt->bind_param(
        "s",
        $email
    );

    $checkStmt->execute();

    $result = $checkStmt->get_result();


    if ($result->num_rows > 0) {

        $checkStmt->close();

        sendResponse(
            false,
            "Email already registered",
            [],
            409
        );
    }


    $checkStmt->close();


    /*
    |--------------------------------------------------------------------------
    | HASH PASSWORD
    |--------------------------------------------------------------------------
    */

    $hashedPassword = password_hash(
        $registerPassword,
        PASSWORD_DEFAULT
    );


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
            password
        )
        VALUES (?, ?, ?, ?)"
    );


    if (!$stmt) {

        sendResponse(
            false,
            "Failed to prepare registration query",
            [],
            500
        );
    }


    $stmt->bind_param(
        "ssss",
        $name,
        $email,
        $phone,
        $hashedPassword
    );


    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        sendResponse(
            false,
            "User registration failed",
            [
                "error" => $error
            ],
            500
        );
    }


    $userId = $stmt->insert_id;

    $stmt->close();


    sendResponse(
        true,
        "User registered successfully",
        [
            "user_id" => $userId,
            "name" => $name,
            "email" => $email,
            "phone" => $phone,
            "role" => "user"
        ],
        201
    );
}


/*
|--------------------------------------------------------------------------
| LOGIN
|--------------------------------------------------------------------------
*/

if ($action === "login") {

    $role = strtolower(
        trim($data["role"] ?? "user")
    );


    $usernameOrEmail = trim(
        $data["email"] ??
        $data["username"] ??
        ""
    );


    $loginPassword = $data["password"] ?? "";


    if (
        $usernameOrEmail === "" ||
        $loginPassword === ""
    ) {

        sendResponse(
            false,
            "Login credentials are required",
            [],
            400
        );
    }


    /*
    |--------------------------------------------------------------------------
    | USER LOGIN
    |--------------------------------------------------------------------------
    */

    if ($role === "user") {

        $stmt = $con->prepare(
            "SELECT
                user_id,
                name,
                email,
                phone,
                password
             FROM userreg_tb
             WHERE email = ?
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
            $usernameOrEmail
        );
    }


    /*
    |--------------------------------------------------------------------------
    | OWNER LOGIN
    |--------------------------------------------------------------------------
    */

    elseif ($role === "owner") {

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
            $usernameOrEmail
        );
    }


    /*
    |--------------------------------------------------------------------------
    | ADMIN LOGIN
    |--------------------------------------------------------------------------
    */

    elseif ($role === "admin") {

        $stmt = $con->prepare(
            "SELECT
                id,
                username,
                password
             FROM adminreg_tb
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
            $usernameOrEmail
        );
    }


    else {

        sendResponse(
            false,
            "Invalid role",
            [],
            400
        );
    }


    /*
    |--------------------------------------------------------------------------
    | EXECUTE LOGIN QUERY
    |--------------------------------------------------------------------------
    */

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
            "Invalid username/email or password",
            [],
            401
        );
    }


    $account = $result->fetch_assoc();


    /*
    |--------------------------------------------------------------------------
    | PASSWORD CHECK
    |--------------------------------------------------------------------------
    */

    if (!password_verify(
        $loginPassword,
        $account["password"]
    )) {

        $stmt->close();

        sendResponse(
            false,
            "Invalid username/email or password",
            [],
            401
        );
    }


    /*
    |--------------------------------------------------------------------------
    | NORMALIZE USER DATA
    |--------------------------------------------------------------------------
    */

    if ($role === "user") {

        $userId = (int) $account["user_id"];

        $name = (string) $account["name"];

        $email = (string) $account["email"];

        $phone = $account["phone"];
    }

    else {

        $userId = (int) $account["id"];

        $name = (string) $account["username"];

        $email = (string) $account["username"];

        $phone = null;
    }


    $stmt->close();


    /*
    |--------------------------------------------------------------------------
    | CREATE TOKENS
    |--------------------------------------------------------------------------
    */

    $accessToken = generateAccessToken(
        $secretKey,
        $issuer,
        $accessTokenExpiry,
        $userId,
        $name,
        $email,
        $role
    );


    $refreshToken = generateRefreshToken(
        $secretKey,
        $issuer,
        $refreshTokenExpiry,
        $userId,
        $email,
        $role
    );


    /*
    |--------------------------------------------------------------------------
    | SAVE TOKENS TO ACCOUNT
    |--------------------------------------------------------------------------
    */

    if ($role === "user") {

        $updateStmt = $con->prepare(
            "UPDATE userreg_tb
             SET token = ?, refresh_token = ?
             WHERE user_id = ?"
        );
    }

    elseif ($role === "owner") {

        $updateStmt = $con->prepare(
            "UPDATE ownerreg_tb
             SET token = ?, refresh_token = ?
             WHERE id = ?"
        );
    }

    else {

        $updateStmt = $con->prepare(
            "UPDATE adminreg_tb
             SET token = ?, refresh_token = ?
             WHERE id = ?"
        );
    }


    if (!$updateStmt) {

        sendResponse(
            false,
            "Failed to prepare token update",
            [],
            500
        );
    }


    $updateStmt->bind_param(
        "ssi",
        $accessToken,
        $refreshToken,
        $userId
    );


    if (!$updateStmt->execute()) {

        $error = $updateStmt->error;

        $updateStmt->close();

        sendResponse(
            false,
            "Failed to save tokens",
            [
                "error" => $error
            ],
            500
        );
    }


    $updateStmt->close();


    /*
    |--------------------------------------------------------------------------
    | SAVE REFRESH TOKEN HASH
    |--------------------------------------------------------------------------
    */

    saveRefreshToken(
        $con,
        $userId,
        $role,
        $refreshToken,
        $refreshTokenExpiry
    );


    /*
    |--------------------------------------------------------------------------
    | LOGIN SUCCESS
    |--------------------------------------------------------------------------
    */

    sendResponse(
        true,
        "Login successful",
        [
            "user_id" => $userId,
            "name" => $name,
            "email" => $email,
            "phone" => $phone,
            "role" => $role,
            "access_token" => $accessToken,
            "refresh_token" => $refreshToken
        ]
    );
}


/*
|--------------------------------------------------------------------------
| REFRESH TOKEN
|--------------------------------------------------------------------------
*/

if ($action === "refresh") {

    $refreshToken = trim(
        $data["refresh_token"] ?? ""
    );


    if ($refreshToken === "") {

        sendResponse(
            false,
            "Refresh token is required",
            [],
            400
        );
    }


    try {

        $decoded = JWT::decode(
            $refreshToken,
            new Key(
                $secretKey,
                "HS256"
            )
        );


        if (($decoded->type ?? "") !== "refresh") {

            sendResponse(
                false,
                "Invalid refresh token",
                [],
                401
            );
        }


        $userId = (int) (
            $decoded->user_id ?? 0
        );


        $email = (string) (
            $decoded->email ?? ""
        );


        $role = (string) (
            $decoded->role ?? ""
        );


        if (
            $userId <= 0 ||
            $email === "" ||
            !in_array(
                $role,
                [
                    "user",
                    "owner",
                    "admin"
                ],
                true
            )
        ) {

            sendResponse(
                false,
                "Invalid refresh token data",
                [],
                401
            );
        }

    } catch (Throwable $e) {

        sendResponse(
            false,
            "Refresh token expired or invalid",
            [],
            401
        );
    }


    /*
    |--------------------------------------------------------------------------
    | CHECK TOKEN IN DATABASE
    |--------------------------------------------------------------------------
    */

    $tokenHash = hash(
        "sha256",
        $refreshToken
    );


    $stmt = $con->prepare(
        "SELECT id
         FROM refresh_tokens
         WHERE token_hash = ?
         AND user_id = ?
         AND revoked = 0
         AND expires_at > NOW()
         LIMIT 1"
    );


    if (!$stmt) {

        sendResponse(
            false,
            "Refresh token database query failed",
            [],
            500
        );
    }


    $stmt->bind_param(
        "si",
        $tokenHash,
        $userId
    );


    $stmt->execute();

    $result = $stmt->get_result();


    if ($result->num_rows === 0) {

        $stmt->close();

        sendResponse(
            false,
            "Refresh token is revoked or expired",
            [],
            401
        );
    }


    $stmt->close();


    /*
    |--------------------------------------------------------------------------
    | GET CURRENT USER DETAILS
    |--------------------------------------------------------------------------
    */

    if ($role === "user") {

        $stmt = $con->prepare(
            "SELECT
                name,
                email,
                phone
             FROM userreg_tb
             WHERE user_id = ?
             LIMIT 1"
        );
    }

    elseif ($role === "owner") {

        $stmt = $con->prepare(
            "SELECT username
             FROM ownerreg_tb
             WHERE id = ?
             LIMIT 1"
        );
    }

    else {

        $stmt = $con->prepare(
            "SELECT username
             FROM adminreg_tb
             WHERE id = ?
             LIMIT 1"
        );
    }


    if (!$stmt) {

        sendResponse(
            false,
            "Failed to get account",
            [],
            500
        );
    }


    $stmt->bind_param(
        "i",
        $userId
    );


    $stmt->execute();

    $result = $stmt->get_result();


    if ($result->num_rows === 0) {

        $stmt->close();

        sendResponse(
            false,
            "Account not found",
            [],
            404
        );
    }


    $currentUser = $result->fetch_assoc();

    $stmt->close();


    if ($role === "user") {

        $name = (string) $currentUser["name"];

        $email = (string) $currentUser["email"];

        $phone = $currentUser["phone"];
    }

    else {

        $name = (string) $currentUser["username"];

        $email = (string) $currentUser["username"];

        $phone = null;
    }


    /*
    |--------------------------------------------------------------------------
    | CREATE NEW ACCESS TOKEN
    |--------------------------------------------------------------------------
    */

    $newAccessToken = generateAccessToken(
        $secretKey,
        $issuer,
        $accessTokenExpiry,
        $userId,
        $name,
        $email,
        $role
    );


    /*
    |--------------------------------------------------------------------------
    | UPDATE ACCESS TOKEN
    |--------------------------------------------------------------------------
    */

    if ($role === "user") {

        $updateStmt = $con->prepare(
            "UPDATE userreg_tb
             SET token = ?
             WHERE user_id = ?"
        );
    }

    elseif ($role === "owner") {

        $updateStmt = $con->prepare(
            "UPDATE ownerreg_tb
             SET token = ?
             WHERE id = ?"
        );
    }

    else {

        $updateStmt = $con->prepare(
            "UPDATE adminreg_tb
             SET token = ?
             WHERE id = ?"
        );
    }


    if (!$updateStmt) {

        sendResponse(
            false,
            "Failed to prepare access token update",
            [],
            500
        );
    }


    $updateStmt->bind_param(
        "si",
        $newAccessToken,
        $userId
    );


    if (!$updateStmt->execute()) {

        $error = $updateStmt->error;

        $updateStmt->close();

        sendResponse(
            false,
            "Failed to update access token",
            [
                "error" => $error
            ],
            500
        );
    }


    $updateStmt->close();


    /*
    |--------------------------------------------------------------------------
    | REFRESH SUCCESS
    |--------------------------------------------------------------------------
    */

    sendResponse(
        true,
        "Access token refreshed successfully",
        [
            "access_token" => $newAccessToken,
            "role" => $role,
            "user_id" => $userId
        ]
    );
}


/*
|--------------------------------------------------------------------------
| LOGOUT
|--------------------------------------------------------------------------
*/

if ($action === "logout") {

    $refreshToken = trim(
        $data["refresh_token"] ?? ""
    );


    if ($refreshToken === "") {

        sendResponse(
            false,
            "Refresh token is required",
            [],
            400
        );
    }


    $tokenHash = hash(
        "sha256",
        $refreshToken
    );


    /*
    |--------------------------------------------------------------------------
    | REVOKE REFRESH TOKEN
    |--------------------------------------------------------------------------
    */

    $stmt = $con->prepare(
        "UPDATE refresh_tokens
         SET revoked = 1
         WHERE token_hash = ?"
    );


    if (!$stmt) {

        sendResponse(
            false,
            "Failed to prepare logout query",
            [],
            500
        );
    }


    $stmt->bind_param(
        "s",
        $tokenHash
    );


    if (!$stmt->execute()) {

        $stmt->close();

        sendResponse(
            false,
            "Logout failed",
            [],
            500
        );
    }


    $stmt->close();


    /*
    |--------------------------------------------------------------------------
    | LOGOUT SUCCESS
    |--------------------------------------------------------------------------
    */

    sendResponse(
        true,
        "Logout successful"
    );
}


/*
|--------------------------------------------------------------------------
| INVALID ACTION
|--------------------------------------------------------------------------
*/

sendResponse(
    false,
    "Invalid action. Use register, login, refresh or logout",
    [],
    400
);