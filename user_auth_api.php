<?php

declare(strict_types=1);

header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(200);
    exit;
}

require_once __DIR__ . "/vendor/autoload.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;


/*
|--------------------------------------------------------------------------
| MYSQLI ERROR MODE
|--------------------------------------------------------------------------
*/

mysqli_report(MYSQLI_REPORT_OFF);


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
| ENVIRONMENT
|--------------------------------------------------------------------------
*/

$host = getenv("DB_HOST");
$port = (int) getenv("DB_PORT");
$dbname = getenv("DB_NAME");
$username = getenv("DB_USER");
$password = getenv("DB_PASSWORD");

$secretKey = getenv("JWT_SECRET");

$issuer = "sporto-api";

$accessTokenExpiry = 900;       // 15 minutes
$refreshTokenExpiry = 2592000;  // 30 days


/*
|--------------------------------------------------------------------------
| ENVIRONMENT CHECK
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
| AIVEN MYSQL SSL CONNECTION
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

    $connected = mysqli_real_connect(
        $con,
        $host,
        $username,
        $password,
        $dbname,
        $port,
        null,
        MYSQLI_CLIENT_SSL
    );

    if (!$connected) {

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
| ACCESS TOKEN
|--------------------------------------------------------------------------
*/

function generateAccessToken(
    string $secretKey,
    string $issuer,
    int $expiry,
    int $userId,
    string $name,
    string $email
): string {

    $issuedAt = time();

    $payload = [
        "iss" => $issuer,
        "iat" => $issuedAt,
        "exp" => $issuedAt + $expiry,
        "user_id" => $userId,
        "name" => $name,
        "email" => $email,
        "role" => "user",
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
| REFRESH TOKEN
|--------------------------------------------------------------------------
*/

function generateRefreshToken(
    string $secretKey,
    string $issuer,
    int $expiry,
    int $userId,
    string $email
): string {

    $issuedAt = time();

    $payload = [
        "iss" => $issuer,
        "iat" => $issuedAt,
        "exp" => $issuedAt + $expiry,
        "user_id" => $userId,
        "email" => $email,
        "role" => "user",
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
| SAVE REFRESH TOKEN
|--------------------------------------------------------------------------
*/

function saveRefreshToken(
    mysqli $con,
    int $userId,
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

    $stmt = $con->prepare(
        "INSERT INTO refresh_tokens
        (
            user_type,
            user_id,
            token_hash,
            expires_at,
            revoked
        )
        VALUES (1, ?, ?, ?, 0)"
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
        "iss",
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
| GET BEARER TOKEN
|--------------------------------------------------------------------------
*/

function getBearerToken(): string
{
    $authorization = "";

    if (isset($_SERVER["HTTP_AUTHORIZATION"])) {

        $authorization = trim(
            $_SERVER["HTTP_AUTHORIZATION"]
        );

    } elseif (function_exists("getallheaders")) {

        $headers = getallheaders();

        foreach ($headers as $key => $value) {

            if (strtolower($key) === "authorization") {

                $authorization = trim($value);

                break;
            }
        }
    }

    if ($authorization === "") {

        sendResponse(
            false,
            "Authorization token is required",
            [],
            401
        );
    }

    if (
        !preg_match(
            "/^Bearer\s+(.+)$/i",
            $authorization,
            $matches
        )
    ) {

        sendResponse(
            false,
            "Invalid Authorization header",
            [],
            401
        );
    }

    return trim($matches[1]);
}


/*
|--------------------------------------------------------------------------
| AUTHENTICATE USER
|--------------------------------------------------------------------------
*/

function authenticateUser(
    string $secretKey,
    string $issuer
): object {

    $token = getBearerToken();

    try {

        $decoded = JWT::decode(
            $token,
            new Key(
                $secretKey,
                "HS256"
            )
        );

    } catch (Throwable $e) {

        sendResponse(
            false,
            "Access token expired or invalid",
            [],
            401
        );
    }

    if (($decoded->type ?? "") !== "access") {

        sendResponse(
            false,
            "Invalid access token",
            [],
            401
        );
    }

    if (($decoded->role ?? "") !== "user") {

        sendResponse(
            false,
            "User access required",
            [],
            403
        );
    }

    if (($decoded->iss ?? "") !== $issuer) {

        sendResponse(
            false,
            "Invalid token issuer",
            [],
            401
        );
    }

    $userId = (int) (
        $decoded->user_id ?? 0
    );

    if ($userId <= 0) {

        sendResponse(
            false,
            "Invalid user information in token",
            [],
            401
        );
    }

    return $decoded;
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

    if (!$checkStmt->execute()) {

        $error = $checkStmt->error;

        $checkStmt->close();

        sendResponse(
            false,
            "Failed to check existing user",
            [
                "error" => $error
            ],
            500
        );
    }

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

    if ($hashedPassword === false) {

        sendResponse(
            false,
            "Failed to secure password",
            [],
            500
        );
    }


    /*
    |--------------------------------------------------------------------------
    | INSERT USER
    |
    | token and refresh_token are inserted as empty strings.
    | This works even if Aiven columns are NOT NULL.
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
        VALUES (?, ?, ?, ?, '', '')"
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

    $userId = (int) $stmt->insert_id;

    $stmt->close();


    if ($userId <= 0) {

        sendResponse(
            false,
            "User registration failed: invalid user ID",
            [],
            500
        );
    }


    /*
    |--------------------------------------------------------------------------
    | GENERATE TOKENS
    |--------------------------------------------------------------------------
    */

    $accessToken = generateAccessToken(
        $secretKey,
        $issuer,
        $accessTokenExpiry,
        $userId,
        $name,
        $email
    );

    $refreshToken = generateRefreshToken(
        $secretKey,
        $issuer,
        $refreshTokenExpiry,
        $userId,
        $email
    );


    /*
    |--------------------------------------------------------------------------
    | SAVE TOKENS
    |--------------------------------------------------------------------------
    */

    $tokenStmt = $con->prepare(
        "UPDATE userreg_tb
         SET token = ?,
             refresh_token = ?
         WHERE user_id = ?"
    );

    if (!$tokenStmt) {

        sendResponse(
            false,
            "User created but token update failed",
            [
                "user_id" => $userId
            ],
            500
        );
    }

    $tokenStmt->bind_param(
        "ssi",
        $accessToken,
        $refreshToken,
        $userId
    );

    if (!$tokenStmt->execute()) {

        $error = $tokenStmt->error;

        $tokenStmt->close();

        sendResponse(
            false,
            "User created but token update failed",
            [
                "user_id" => $userId,
                "error" => $error
            ],
            500
        );
    }

    $tokenStmt->close();


    /*
    |--------------------------------------------------------------------------
    | SAVE REFRESH TOKEN HASH
    |--------------------------------------------------------------------------
    */

    saveRefreshToken(
        $con,
        $userId,
        $refreshToken,
        $refreshTokenExpiry
    );


    /*
    |--------------------------------------------------------------------------
    | REGISTER SUCCESS
    |--------------------------------------------------------------------------
    */

    sendResponse(
        true,
        "User registered successfully",
        [
            "user_id" => $userId,
            "name" => $name,
            "email" => $email,
            "phone" => $phone,
            "profile_image_url" => null,
            "role" => "user",
            "access_token" => $accessToken,
            "refresh_token" => $refreshToken
        ],
        201
    );
}


/*
|--------------------------------------------------------------------------
| USER LOGIN
|--------------------------------------------------------------------------
*/

if ($action === "login") {

    $email = strtolower(
        trim($data["email"] ?? "")
    );

    $loginPassword = $data["password"] ?? "";


    if (
        $email === "" ||
        $loginPassword === ""
    ) {

        sendResponse(
            false,
            "Email and password are required",
            [],
            400
        );
    }


    $stmt = $con->prepare(
        "SELECT
            user_id,
            name,
            email,
            phone,
            password,
            profile_image_url
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
        $email
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
            "Invalid email or password",
            [],
            401
        );
    }


    $user = $result->fetch_assoc();

    $stmt->close();


    if (!password_verify(
        $loginPassword,
        $user["password"]
    )) {

        sendResponse(
            false,
            "Invalid email or password",
            [],
            401
        );
    }


    $userId = (int) $user["user_id"];

    $name = (string) $user["name"];

    $userEmail = (string) $user["email"];

    $phone = $user["phone"];

    $profileImageUrl = $user["profile_image_url"];


    /*
    |--------------------------------------------------------------------------
    | GENERATE TOKENS
    |--------------------------------------------------------------------------
    */

    $accessToken = generateAccessToken(
        $secretKey,
        $issuer,
        $accessTokenExpiry,
        $userId,
        $name,
        $userEmail
    );


    $refreshToken = generateRefreshToken(
        $secretKey,
        $issuer,
        $refreshTokenExpiry,
        $userId,
        $userEmail
    );


    /*
    |--------------------------------------------------------------------------
    | SAVE TOKENS IN USER TABLE
    |--------------------------------------------------------------------------
    */

    $updateStmt = $con->prepare(
        "UPDATE userreg_tb
         SET token = ?,
             refresh_token = ?
         WHERE user_id = ?"
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
        $refreshToken,
        $refreshTokenExpiry
    );


    sendResponse(
        true,
        "Login successful",
        [
            "user_id" => $userId,
            "name" => $name,
            "email" => $userEmail,
            "phone" => $phone,
            "profile_image_url" => $profileImageUrl,
            "role" => "user",
            "access_token" => $accessToken,
            "refresh_token" => $refreshToken
        ]
    );
}


/*
|--------------------------------------------------------------------------
| GET PROFILE
|--------------------------------------------------------------------------
*/

if ($action === "get_profile") {

    $decoded = authenticateUser(
        $secretKey,
        $issuer
    );

    $userId = (int) $decoded->user_id;


    $stmt = $con->prepare(
        "SELECT
            user_id,
            name,
            email,
            phone,
            profile_image_url
         FROM userreg_tb
         WHERE user_id = ?
         LIMIT 1"
    );


    if (!$stmt) {

        sendResponse(
            false,
            "Failed to prepare profile query",
            [],
            500
        );
    }


    $stmt->bind_param(
        "i",
        $userId
    );

    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        sendResponse(
            false,
            "Failed to get profile",
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
            "User not found",
            [],
            404
        );
    }


    $user = $result->fetch_assoc();

    $stmt->close();


    sendResponse(
        true,
        "Profile fetched successfully",
        [
            "user" => [
                "user_id" => (int) $user["user_id"],
                "name" => $user["name"],
                "email" => $user["email"],
                "phone" => $user["phone"],
                "profile_image_url" => $user["profile_image_url"],
                "role" => "user"
            ]
        ]
    );
}


/*
|--------------------------------------------------------------------------
| UPDATE PROFILE
|--------------------------------------------------------------------------
*/

if ($action === "update_profile") {

    $decoded = authenticateUser(
        $secretKey,
        $issuer
    );

    $userId = (int) $decoded->user_id;


    /*
    | GET CURRENT USER
    */

    $stmt = $con->prepare(
        "SELECT
            name,
            email,
            phone,
            profile_image_url
         FROM userreg_tb
         WHERE user_id = ?
         LIMIT 1"
    );


    if (!$stmt) {

        sendResponse(
            false,
            "Failed to prepare profile query",
            [],
            500
        );
    }


    $stmt->bind_param(
        "i",
        $userId
    );

    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        sendResponse(
            false,
            "Failed to get current profile",
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
            "User not found",
            [],
            404
        );
    }


    $currentUser = $result->fetch_assoc();

    $stmt->close();


    /*
    | UPDATED VALUES
    */

    $name = array_key_exists("name", $data)
        ? trim((string) $data["name"])
        : (string) $currentUser["name"];


    $email = array_key_exists("email", $data)
        ? strtolower(trim((string) $data["email"]))
        : (string) $currentUser["email"];


    $phone = array_key_exists("phone", $data)
        ? trim((string) $data["phone"])
        : (string) $currentUser["phone"];


    /*
    | PROFILE IMAGE
    */

    if (array_key_exists("profile_image_url", $data)) {

        $profileImageUrl = $data["profile_image_url"];

        if ($profileImageUrl !== null) {

            $profileImageUrl = trim(
                (string) $profileImageUrl
            );

            if ($profileImageUrl === "") {
                $profileImageUrl = null;
            }
        }

    } else {

        $profileImageUrl = $currentUser["profile_image_url"];
    }


    /*
    | VALIDATION
    */

    if ($name === "") {

        sendResponse(
            false,
            "Name cannot be empty",
            [],
            400
        );
    }


    if ($email === "") {

        sendResponse(
            false,
            "Email cannot be empty",
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


    if ($phone === "") {

        sendResponse(
            false,
            "Phone cannot be empty",
            [],
            400
        );
    }


    /*
    | CHECK EMAIL DUPLICATE
    */

    $checkStmt = $con->prepare(
        "SELECT user_id
         FROM userreg_tb
         WHERE email = ?
         AND user_id != ?
         LIMIT 1"
    );


    if (!$checkStmt) {

        sendResponse(
            false,
            "Failed to prepare email check",
            [],
            500
        );
    }


    $checkStmt->bind_param(
        "si",
        $email,
        $userId
    );

    if (!$checkStmt->execute()) {

        $error = $checkStmt->error;

        $checkStmt->close();

        sendResponse(
            false,
            "Email check failed",
            [
                "error" => $error
            ],
            500
        );
    }

    $emailResult = $checkStmt->get_result();


    if ($emailResult->num_rows > 0) {

        $checkStmt->close();

        sendResponse(
            false,
            "Email is already used by another account",
            [],
            409
        );
    }


    $checkStmt->close();


    /*
    | UPDATE PROFILE
    */

    $updateStmt = $con->prepare(
        "UPDATE userreg_tb
         SET
            name = ?,
            email = ?,
            phone = ?,
            profile_image_url = ?
         WHERE user_id = ?"
    );


    if (!$updateStmt) {

        sendResponse(
            false,
            "Failed to prepare profile update",
            [],
            500
        );
    }


    $updateStmt->bind_param(
        "ssssi",
        $name,
        $email,
        $phone,
        $profileImageUrl,
        $userId
    );


    if (!$updateStmt->execute()) {

        $error = $updateStmt->error;

        $updateStmt->close();

        sendResponse(
            false,
            "Profile update failed",
            [
                "error" => $error
            ],
            500
        );
    }


    $updateStmt->close();


    /*
    | GENERATE NEW ACCESS TOKEN
    */

    $newAccessToken = generateAccessToken(
        $secretKey,
        $issuer,
        $accessTokenExpiry,
        $userId,
        $name,
        $email
    );


    $tokenStmt = $con->prepare(
        "UPDATE userreg_tb
         SET token = ?
         WHERE user_id = ?"
    );


    if (!$tokenStmt) {

        sendResponse(
            false,
            "Profile updated but failed to refresh access token",
            [
                "user_id" => $userId,
                "name" => $name,
                "email" => $email,
                "phone" => $phone,
                "profile_image_url" => $profileImageUrl
            ],
            500
        );
    }


    $tokenStmt->bind_param(
        "si",
        $newAccessToken,
        $userId
    );


    if (!$tokenStmt->execute()) {

        $error = $tokenStmt->error;

        $tokenStmt->close();

        sendResponse(
            false,
            "Profile updated but failed to refresh access token",
            [
                "error" => $error
            ],
            500
        );
    }


    $tokenStmt->close();


    sendResponse(
        true,
        "Profile updated successfully",
        [
            "user" => [
                "user_id" => $userId,
                "name" => $name,
                "email" => $email,
                "phone" => $phone,
                "profile_image_url" => $profileImageUrl,
                "role" => "user"
            ],
            "access_token" => $newAccessToken
        ]
    );
}


/*
|--------------------------------------------------------------------------
| REFRESH
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

        if (($decoded->role ?? "") !== "user") {

            sendResponse(
                false,
                "Invalid refresh token role",
                [],
                401
            );
        }

        if (($decoded->iss ?? "") !== $issuer) {

            sendResponse(
                false,
                "Invalid refresh token issuer",
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

        if (
            $userId <= 0 ||
            $email === ""
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
    | CHECK DATABASE REFRESH TOKEN
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
         AND user_type = 1
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

    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        sendResponse(
            false,
            "Refresh token query failed",
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
            "Refresh token is revoked or expired",
            [],
            401
        );
    }

    $stmt->close();


    /*
    | GET USER
    */

    $stmt = $con->prepare(
        "SELECT
            name,
            email,
            phone,
            profile_image_url
         FROM userreg_tb
         WHERE user_id = ?
         LIMIT 1"
    );


    if (!$stmt) {

        sendResponse(
            false,
            "Failed to get user",
            [],
            500
        );
    }


    $stmt->bind_param(
        "i",
        $userId
    );

    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        sendResponse(
            false,
            "Failed to get user",
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
            "User not found",
            [],
            404
        );
    }


    $user = $result->fetch_assoc();

    $stmt->close();


    $name = (string) $user["name"];

    $userEmail = (string) $user["email"];

    $phone = $user["phone"];

    $profileImageUrl = $user["profile_image_url"];


    /*
    | NEW ACCESS TOKEN
    */

    $newAccessToken = generateAccessToken(
        $secretKey,
        $issuer,
        $accessTokenExpiry,
        $userId,
        $name,
        $userEmail
    );


    /*
    | UPDATE ACCESS TOKEN
    */

    $updateStmt = $con->prepare(
        "UPDATE userreg_tb
         SET token = ?
         WHERE user_id = ?"
    );


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


    sendResponse(
        true,
        "Access token refreshed successfully",
        [
            "access_token" => $newAccessToken,
            "refresh_token" => $refreshToken,
            "user_id" => $userId,
            "name" => $name,
            "email" => $userEmail,
            "phone" => $phone,
            "profile_image_url" => $profileImageUrl,
            "role" => "user"
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


    $stmt = $con->prepare(
        "UPDATE refresh_tokens
         SET revoked = 1
         WHERE token_hash = ?
         AND user_type = 1"
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

        $error = $stmt->error;

        $stmt->close();

        sendResponse(
            false,
            "Logout failed",
            [
                "error" => $error
            ],
            500
        );
    }


    $stmt->close();


    /*
    | CLEAR USER TOKENS
    */

    $stmt = $con->prepare(
        "UPDATE userreg_tb
         SET token = NULL,
             refresh_token = NULL
         WHERE refresh_token = ?"
    );


    if ($stmt) {

        $stmt->bind_param(
            "s",
            $refreshToken
        );

        $stmt->execute();

        $stmt->close();
    }


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
    "Invalid action. Use register, login, get_profile, update_profile, refresh or logout",
    [],
    400
);