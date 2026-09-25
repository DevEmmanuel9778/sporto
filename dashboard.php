
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
    "Access-Control-Allow-Methods: GET, OPTIONS"
);
header(
    "Access-Control-Allow-Headers: Content-Type, Authorization"
);
header("Access-Control-Max-Age: 86400");

// ======================================================
// OPTIONS
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
require_once dirname(__DIR__) . "/connection.php";
require_once dirname(__DIR__) . "/vendor/autoload.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

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
// GET BEARER TOKEN
// ======================================================
function getBearerToken(): ?string
{
    $authorization = null;

    // getallheaders()
    if (function_exists("getallheaders")) {
        $headers = getallheaders();

        foreach ($headers as $key => $value) {
            if (
                strtolower((string) $key) ===
                "authorization"
            ) {
                $authorization = (string) $value;
                break;
            }
        }
    }

    // Apache / Render
    if (!$authorization) {
        $authorization =
            $_SERVER["HTTP_AUTHORIZATION"] ?? null;
    }

    // Additional fallback
    if (!$authorization) {
        $authorization =
            $_SERVER["REDIRECT_HTTP_AUTHORIZATION"] ?? null;
    }

    if (
        !$authorization ||
        !preg_match(
            "/^Bearer\s+(.+)$/i",
            trim($authorization),
            $matches
        )
    ) {
        return null;
    }

    return trim($matches[1]);
}

// ======================================================
// ADMIN AUTHENTICATION
// ======================================================
function authenticateAdmin(): array
{
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

    $token = getBearerToken();

    if (!$token) {
        sendResponse(
            false,
            "Authorization token is required",
            [],
            401
        );
    }

    try {
        $decoded = JWT::decode(
            $token,
            new Key(
                $secretKey,
                "HS256"
            )
        );

        $payload = (array) $decoded;

        // Only access tokens
        if (
            ($payload["type"] ?? "") !==
            "access"
        ) {
            sendResponse(
                false,
                "Invalid access token",
                [],
                401
            );
        }

        // Admin only
        $role = strtolower(
            trim(
                (string) (
                    $payload["role"] ?? ""
                )
            )
        );

        if ($role !== "admin") {
            sendResponse(
                false,
                "Admin access required",
                [],
                403
            );
        }

        $userId = (int) (
            $payload["user_id"]
            ?? $payload["id"]
            ?? 0
        );

        if ($userId <= 0) {
            sendResponse(
                false,
                "Invalid admin user ID",
                [],
                401
            );
        }

        return $payload;

    } catch (Throwable $e) {
        sendResponse(
            false,
            "Invalid or expired token",
            [],
            401
        );
    }
}

// ======================================================
// CHECK TABLE EXISTS
// ======================================================
function tableExists(
    mysqli $con,
    string $tableName
): bool {
    $stmt = $con->prepare(
        "SELECT COUNT(*) AS total
         FROM information_schema.tables
         WHERE table_schema = DATABASE()
         AND table_name = ?
         LIMIT 1"
    );

    if (!$stmt) {
        return false;
    }

    $stmt->bind_param(
        "s",
        $tableName
    );

    if (!$stmt->execute()) {
        $stmt->close();
        return false;
    }

    $result = $stmt->get_result();

    if (!$result) {
        $stmt->close();
        return false;
    }

    $row = $result->fetch_assoc();

    $stmt->close();

    return (int) (
        $row["total"] ?? 0
    ) > 0;
}

// ======================================================
// COUNT TABLE ROWS
// ======================================================
function countRows(
    mysqli $con,
    string $tableName
): int {
    if (
        !tableExists(
            $con,
            $tableName
        )
    ) {
        return 0;
    }

    // Table names are selected only from our
    // internal fixed list, never from user input.
    $sql =
        "SELECT COUNT(*) AS total
         FROM `" .
        str_replace(
            "`",
            "``",
            $tableName
        ) .
        "`";

    $result = $con->query($sql);

    if (!$result) {
        return 0;
    }

    $row = $result->fetch_assoc();

    return (int) (
        $row["total"] ?? 0
    );
}

// ======================================================
// COUNT TURFS
// ======================================================
function countTurfs(
    mysqli $con
): int {
    if (
        !tableExists(
            $con,
            "turf_tb"
        )
    ) {
        return 0;
    }

    $result = $con->query(
        "SELECT COUNT(*) AS total
         FROM turf_tb
         WHERE status != 'deleted'"
    );

    if (!$result) {
        return 0;
    }

    $row = $result->fetch_assoc();

    return (int) (
        $row["total"] ?? 0
    );
}

// ======================================================
// FIND FIRST EXISTING TABLE
// ======================================================
function findExistingTable(
    mysqli $con,
    array $candidates
): ?string {
    foreach ($candidates as $table) {
        if (
            tableExists(
                $con,
                $table
            )
        ) {
            return $table;
        }
    }

    return null;
}

// ======================================================
// REQUEST METHOD
// ======================================================
$method = strtoupper(
    $_SERVER["REQUEST_METHOD"] ?? ""
);

if ($method !== "GET") {
    sendResponse(
        false,
        "Only GET requests are allowed",
        [],
        405
    );
}

// ======================================================
// AUTH
// ======================================================
$admin = authenticateAdmin();

// ======================================================
// DATABASE CHECK
// ======================================================
if (!isset($con) || !($con instanceof mysqli)) {
    sendResponse(
        false,
        "Database connection is unavailable",
        [],
        500
    );
}

if ($con->connect_errno) {
    sendResponse(
        false,
        "Database connection failed",
        [
            "error" => $con->connect_error,
        ],
        500
    );
}

$con->set_charset("utf8mb4");

// ======================================================
// DASHBOARD COUNTS
// ======================================================
try {

    // --------------------------------------------------
    // USERS
    // --------------------------------------------------
    $totalUsers = countRows(
        $con,
        "reg_tb"
    );

    // --------------------------------------------------
    // OWNERS
    // --------------------------------------------------
    $totalOwners = countRows(
        $con,
        "ownerreg_tb"
    );

    // --------------------------------------------------
    // TURFS
    // --------------------------------------------------
    $totalTurfs = countTurfs(
        $con
    );

    // --------------------------------------------------
    // BOOKINGS
    // --------------------------------------------------
    $totalBookings = countRows(
        $con,
        "bookings"
    );

    // --------------------------------------------------
    // PAYMENTS
    //
    // Supports common table names.
    // If none exists, returns 0.
    // --------------------------------------------------
    $paymentTable =
        findExistingTable(
            $con,
            [
                "payments",
                "payment_tb",
                "payments_tb",
                "payment",
            ]
        );

    $totalPayments = $paymentTable === null
        ? 0
        : countRows(
            $con,
            $paymentTable
        );

    // --------------------------------------------------
    // PRODUCTS
    //
    // Supports common table names.
    // If none exists, returns 0.
    // --------------------------------------------------
    $productTable =
        findExistingTable(
            $con,
            [
                "products",
                "product_tb",
                "products_tb",
                "product",
            ]
        );

    $totalProducts = $productTable === null
        ? 0
        : countRows(
            $con,
            $productTable
        );

    // --------------------------------------------------
    // ORDERS
    //
    // Supports common table names.
    // If none exists, returns 0.
    // --------------------------------------------------
    $orderTable =
        findExistingTable(
            $con,
            [
                "orders",
                "order_tb",
                "orders_tb",
                "order",
            ]
        );

    $totalOrders = $orderTable === null
        ? 0
        : countRows(
            $con,
            $orderTable
        );

    // ==================================================
    // SUCCESS RESPONSE
    // ==================================================
    sendResponse(
        true,
        "Admin dashboard fetched successfully",
        [
            "dashboard" => [
                "total_users" => $totalUsers,
                "total_owners" => $totalOwners,
                "total_turfs" => $totalTurfs,
                "total_bookings" => $totalBookings,
                "total_payments" => $totalPayments,
                "total_products" => $totalProducts,
                "total_orders" => $totalOrders,
            ],
        ],
        200
    );

} catch (Throwable $e) {

    sendResponse(
        false,
        "Failed to load admin dashboard",
        [
            "error" => $e->getMessage(),
            "file" => basename(
                $e->getFile()
            ),
            "line" => $e->getLine(),
        ],
        500
    );
}
