
<?php

// ======================================================
// ERROR HANDLING
// ======================================================
ini_set("display_errors", "0");
ini_set("log_errors", "1");
error_reporting(E_ALL);

mysqli_report(MYSQLI_REPORT_OFF);

// ======================================================
// HEADERS / CORS
// ======================================================
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header(
    "Access-Control-Allow-Headers: Content-Type, Authorization"
);
header("Access-Control-Max-Age: 86400");

// ======================================================
// OPTIONS / PREFLIGHT
// ======================================================
if (
    ($_SERVER["REQUEST_METHOD"] ?? "") === "OPTIONS"
) {
    http_response_code(204);
    exit;
}

// ======================================================
// REQUIRED FILES
// ======================================================
require_once __DIR__ . "/vendor/autoload.php";

use Firebase\JWT\JWT;

// ======================================================
// RESPONSE HELPER
// ======================================================
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
                "message" => $message,
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE
        | JSON_UNESCAPED_SLASHES
        | JSON_INVALID_UTF8_SUBSTITUTE
    );

    exit;
}

// ======================================================
// REQUEST METHOD
// ======================================================
$method = strtoupper(
    $_SERVER["REQUEST_METHOD"] ?? ""
);

if ($method !== "POST") {
    sendResponse(
        false,
        "Only POST requests are allowed",
        [],
        405
    );
}

// ======================================================
// READ JSON BODY
// ======================================================
$rawInput = file_get_contents("php://input");

if (
    $rawInput === false ||
    trim($rawInput) === ""
) {
    sendResponse(
        false,
        "Request body is required",
        [],
        400
    );
}

$data = json_decode(
    $rawInput,
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

// ======================================================
// ACTION
// ======================================================
$action = strtolower(
    trim(
        (string) (
            $data["action"] ?? ""
        )
    )
);

if ($action !== "login") {
    sendResponse(
        false,
        "Invalid action. Use login",
        [],
        400
    );
}

// ======================================================
// PERMANENT ADMIN CREDENTIALS
// ======================================================
//
// ONLY these credentials can access Admin.
//
// Username:
// sporto_root_admin
//
// Password:
// Spt0!Adm#92_Kx@7Qm
//
// No admin registration is supported.
// ======================================================
$permanentUsername = "sporto_root_admin";
$permanentPassword = "Spt0!Adm#92_Kx@7Qm";

// ======================================================
// LOGIN INPUT
// ======================================================
$loginUsername = trim(
    (string) (
        $data["username"]
        ?? $data["email"]
        ?? ""
    )
);

$loginPassword = (string) (
    $data["password"] ?? ""
);

if (
    $loginUsername === "" ||
    $loginPassword === ""
) {
    sendResponse(
        false,
        "Username and password are required",
        [],
        400
    );
}

// ======================================================
// CHECK PERMANENT CREDENTIALS
// ======================================================
$usernameValid = hash_equals(
    $permanentUsername,
    $loginUsername
);

$passwordValid = hash_equals(
    $permanentPassword,
    $loginPassword
);

if (
    !$usernameValid ||
    !$passwordValid
) {
    sendResponse(
        false,
        "Invalid username or password",
        [],
        401
    );
}

// ======================================================
// JWT SECRET
// ======================================================
$secretKey = getenv("JWT_SECRET");

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

// ======================================================
// DATABASE ENVIRONMENT
// ======================================================
$dbHost = getenv("DB_HOST");
$dbPort = (int) (
    getenv("DB_PORT") ?: 0
);
$dbName = getenv("DB_NAME");
$dbUser = getenv("DB_USER");
$dbPassword = getenv("DB_PASSWORD");

if (
    $dbHost === false ||
    trim($dbHost) === "" ||
    $dbPort <= 0 ||
    $dbName === false ||
    trim($dbName) === "" ||
    $dbUser === false ||
    trim($dbUser) === "" ||
    $dbPassword === false
) {
    sendResponse(
        false,
        "Database environment variables are missing or invalid",
        [],
        500
    );
}

// ======================================================
// AIVEN SSL CONNECTION
// ======================================================
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
        $dbHost,
        $dbUser,
        $dbPassword,
        $dbName,
        $dbPort,
        null,
        MYSQLI_CLIENT_SSL
    );

    if (!$connected) {
        throw new RuntimeException(
            mysqli_connect_error()
                ?: "Unknown database connection error"
        );
    }

} catch (Throwable $e) {
    sendResponse(
        false,
        "Database connection failed",
        [
            "error" => $e->getMessage(),
        ],
        500
    );
}

$con->set_charset("utf8mb4");

// ======================================================
// FIND THE SINGLE ADMIN RECORD
// ======================================================
//
// Login credentials are NOT read from password column.
// Username is used to locate the admin row so we can get
// the admin ID and save the JWT token.
// ======================================================
$stmt = $con->prepare(
    "SELECT
        id,
        username
     FROM adminreg_tb
     WHERE username = ?
     LIMIT 1"
);

if (!$stmt) {
    $con->close();

    sendResponse(
        false,
        "Failed to prepare admin query",
        [
            "error" => $con->error,
        ],
        500
    );
}

$stmt->bind_param(
    "s",
    $permanentUsername
);

if (!$stmt->execute()) {
    $error = $stmt->error;

    $stmt->close();
    $con->close();

    sendResponse(
        false,
        "Admin lookup failed",
        [
            "error" => $error,
        ],
        500
    );
}

$result = $stmt->get_result();

if ($result === false) {
    $error = $stmt->error;

    $stmt->close();
    $con->close();

    sendResponse(
        false,
        "Failed to read admin record",
        [
            "error" => $error,
        ],
        500
    );
}

// ======================================================
// ADMIN RECORD MUST EXIST
// ======================================================
if ($result->num_rows === 0) {
    $stmt->close();
    $con->close();

    sendResponse(
        false,
        "Admin account is not configured in adminreg_tb",
        [],
        500
    );
}

$admin = $result->fetch_assoc();

$stmt->close();

// ======================================================
// ADMIN ID
// ======================================================
$adminId = (int) (
    $admin["id"] ?? 0
);

if ($adminId <= 0) {
    $con->close();

    sendResponse(
        false,
        "Invalid admin account ID",
        [],
        500
    );
}

$adminName = $permanentUsername;

// ======================================================
// CREATE JWT
// ======================================================
//
// 30-day access token so reopening the app does not force
// the admin to login again every 15 minutes.
//
// Logout on Flutter clears the local token.
// ======================================================
$issuedAt = time();

$expiresAt = $issuedAt + (30 * 24 * 60 * 60);

$accessToken = JWT::encode(
    [
        "iss" => "sporto-api",
        "iat" => $issuedAt,
        "exp" => $expiresAt,

        "user_id" => $adminId,
        "name" => $adminName,
        "email" => $adminName,
        "role" => "admin",
        "type" => "access",
    ],
    $secretKey,
    "HS256"
);

// ======================================================
// SAVE TOKEN
// ======================================================
$updateStmt = $con->prepare(
    "UPDATE adminreg_tb
     SET token = ?
     WHERE id = ?"
);

if (!$updateStmt) {
    $con->close();

    sendResponse(
        false,
        "Failed to prepare token update",
        [
            "error" => $con->error,
        ],
        500
    );
}

$updateStmt->bind_param(
    "si",
    $accessToken,
    $adminId
);

if (!$updateStmt->execute()) {
    $error = $updateStmt->error;

    $updateStmt->close();
    $con->close();

    sendResponse(
        false,
        "Failed to save admin token",
        [
            "error" => $error,
        ],
        500
    );
}

$updateStmt->close();
$con->close();

// ======================================================
// SUCCESS RESPONSE
// ======================================================
sendResponse(
    true,
    "Admin login successful",
    [
        "user_id" => $adminId,
        "name" => $adminName,
        "email" => $adminName,
        "role" => "admin",
        "access_token" => $accessToken,
        "expires_in" => $expiresAt - $issuedAt,
    ],
    200
);
