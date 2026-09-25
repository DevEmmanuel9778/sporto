
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
header(
    "Access-Control-Allow-Methods: POST, OPTIONS"
);
header(
    "Access-Control-Allow-Headers: Content-Type, Authorization"
);
header("Access-Control-Max-Age: 86400");

// Preflight
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
// ONLY POST
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
// READ JSON REQUEST
// ======================================================
$input = file_get_contents("php://input");

$data = [];

if (
    $input !== false &&
    trim($input) !== ""
) {
    $decoded = json_decode(
        $input,
        true
    );

    if (!is_array($decoded)) {
        sendResponse(
            false,
            "Invalid JSON request",
            [],
            400
        );
    }

    $data = $decoded;
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
// PERMANENT ADMIN CREDENTIALS
// ======================================================
//
// These are the only credentials allowed.
//
// Username:
// sporto_root_admin
//
// Password:
// Spt0!Adm#92_Kx@7Qm
//
// For production security, these can later be moved
// to Render Environment Variables without changing
// the Flutter login flow.
// ======================================================

$permanentUsername = "sporto_root_admin";
$permanentPassword = "Spt0!Adm#92_Kx@7Qm";

// ======================================================
// LOGIN DATA
// ======================================================
$adminUsername = trim(
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
    $adminUsername === "" ||
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
// PERMANENT CREDENTIAL CHECK
// ======================================================
if (
    !hash_equals(
        $permanentUsername,
        $adminUsername
    ) ||
    !hash_equals(
        $permanentPassword,
        $loginPassword
    )
) {
    sendResponse(
        false,
        "Invalid username or password",
        [],
        401
    );
}

// ======================================================
// DATABASE ENVIRONMENT
// ======================================================
$host = getenv("DB_HOST");
$port = (int) (
    getenv("DB_PORT") ?: 0
);
$dbname = getenv("DB_NAME");
$dbUsername = getenv("DB_USER");
$dbPassword = getenv("DB_PASSWORD");

if (
    $host === false ||
    trim($host) === "" ||
    $port <= 0 ||
    $dbname === false ||
    trim($dbname) === "" ||
    $dbUsername === false ||
    trim($dbUsername) === "" ||
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
// AIVEN SSL DATABASE CONNECTION
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
        $host,
        $dbUsername,
        $dbPassword,
        $dbname,
        $port,
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
// FIND ADMIN RECORD
// ======================================================
//
// We still use adminreg_tb to get the actual admin ID
// and to save the issued JWT token.
//
// The password in this table is NOT used for login.
// The permanent credentials above control login.
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
    sendResponse(
        false,
        "Database query failed",
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
// ADMIN RECORD MISSING
// ======================================================
if ($result->num_rows === 0) {
    $stmt->close();

    sendResponse(
        false,
        "Permanent admin account is not configured in adminreg_tb",
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
$issuedAt = time();

$accessToken = JWT::encode(
    [
        "iss" => "sporto-api",
        "iat" => $issuedAt,
        "exp" => $issuedAt + 900,

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
     SET token = ?,
         username = ?
     WHERE id = ?"
);

if (!$updateStmt) {
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
    "ssi",
    $accessToken,
    $adminName,
    $adminId
);

if (!$updateStmt->execute()) {
    $error = $updateStmt->error;

    $updateStmt->close();

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

// ======================================================
// SUCCESS
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
        "expires_in" => 900,
    ],
    200
);