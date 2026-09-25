<?php

header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(200);
    exit;
}

require_once dirname(__DIR__) . "/connection.php";
require_once dirname(__DIR__) . "/vendor/autoload.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function response(
    bool $status,
    string $message,
    array $data = [],
    int $code = 200
): never {
    http_response_code($code);

    echo json_encode([
        "status" => $status,
        "message" => $message,
        ...$data
    ]);

    exit;
}

function getBearerToken(): ?string
{
    $headers = function_exists("getallheaders")
        ? getallheaders()
        : [];

    $authorization =
        $headers["Authorization"]
        ?? $headers["authorization"]
        ?? ($_SERVER["HTTP_AUTHORIZATION"] ?? null);

    if (
        !$authorization ||
        !preg_match(
            "/Bearer\s+(.+)/i",
            $authorization,
            $matches
        )
    ) {
        return null;
    }

    return trim($matches[1]);
}

function authenticateAdmin(
    string $secretKey
): array {

    $token = getBearerToken();

    if (!$token) {
        response(
            false,
            "Authorization token is required",
            [],
            401
        );
    }

    try {
        $decoded = JWT::decode(
            $token,
            new Key($secretKey, "HS256")
        );

        $payload = (array) $decoded;

    } catch (Throwable $e) {
        response(
            false,
            "Invalid or expired access token",
            [],
            401
        );
    }

    if (($payload["type"] ?? "") !== "access") {
        response(
            false,
            "Invalid access token",
            [],
            401
        );
    }

    if (($payload["role"] ?? "") !== "admin") {
        response(
            false,
            "Admin access required",
            [],
            403
        );
    }

    $adminId = (int) (
        $payload["user_id"] ?? 0
    );

    if ($adminId <= 0) {
        response(
            false,
            "Invalid admin information",
            [],
            401
        );
    }

    return $payload;
}

function getRequestData(): array
{
    $raw = file_get_contents("php://input");

    if (
        $raw !== false &&
        trim($raw) !== ""
    ) {
        $decoded = json_decode(
            $raw,
            true
        );

        if (is_array($decoded)) {
            return $decoded;
        }
    }

    return $_POST;
}

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
    response(
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
    response(
        false,
        "JWT_SECRET environment variable is missing",
        [],
        500
    );
}

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

    if (
        !mysqli_real_connect(
            $con,
            $host,
            $username,
            $password,
            $dbname,
            $port,
            null,
            MYSQLI_CLIENT_SSL
        )
    ) {
        throw new RuntimeException(
            mysqli_connect_error()
            ?: "Unknown database connection error"
        );
    }

} catch (Throwable $e) {

    response(
        false,
        "Database connection failed",
        [
            "error" => $e->getMessage()
        ],
        500
    );
}

$con->set_charset("utf8mb4");

$adminPayload = authenticateAdmin(
    $secretKey
);

$adminId = (int) (
    $adminPayload["user_id"] ?? 0
);

$data = getRequestData();

$type = strtolower(
    trim(
        (string) (
            $data["type"] ?? "general"
        )
    )
);

$target = strtolower(
    trim(
        (string) (
            $data["target"] ?? ""
        )
    )
);

$title = trim(
    (string) (
        $data["title"] ?? ""
    )
);

$message = trim(
    (string) (
        $data["message"] ?? ""
    )
);

$recipientId = (int) (
    $data["recipient_id"] ?? 0
);

$allowedTypes = [
    "general",
    "booking",
    "payment",
    "offer",
    "turf",
    "order",
    "announcement"
];

if (!in_array($type, $allowedTypes, true)) {
    response(
        false,
        "Invalid notification type",
        [],
        422
    );
}

$allowedTargets = [
    "all_users",
    "selected_user",
    "all_admins",
    "selected_admin"
];

if (!in_array($target, $allowedTargets, true)) {
    response(
        false,
        "Invalid notification target",
        [],
        422
    );
}

if ($title === "") {
    response(
        false,
        "Notification title is required",
        [],
        422
    );
}

if ($message === "") {
    response(
        false,
        "Notification message is required",
        [],
        422
    );
}

if (strlen($title) > 255) {
    response(
        false,
        "Notification title is too long",
        [],
        422
    );
}

$con->begin_transaction();

try {

    $createdCount = 0;

    /*
    |--------------------------------------------------------------------------
    | ALL USERS
    |--------------------------------------------------------------------------
    */

    if ($target === "all_users") {

        $usersStmt = $con->prepare(
            "SELECT user_id
             FROM userreg_tb
             ORDER BY user_id ASC"
        );

        if (!$usersStmt) {
            throw new RuntimeException(
                "Failed to prepare user query"
            );
        }

        if (!$usersStmt->execute()) {

            $error = $usersStmt->error;

            $usersStmt->close();

            throw new RuntimeException(
                $error ?: "Failed to fetch users"
            );
        }

        $result = $usersStmt->get_result();

        $insertStmt = $con->prepare(
            "INSERT INTO notifications
            (
                user_id,
                admin_id,
                title,
                message,
                type,
                is_read
            )
            VALUES (?, NULL, ?, ?, ?, 0)"
        );

        if (!$insertStmt) {

            $usersStmt->close();

            throw new RuntimeException(
                "Failed to prepare notification insert"
            );
        }

        while (
            $user = $result->fetch_assoc()
        ) {

            $userId = (int) (
                $user["user_id"]
            );

            $insertStmt->bind_param(
                "isss",
                $userId,
                $title,
                $message,
                $type
            );

            if (!$insertStmt->execute()) {

                $error =
                    $insertStmt->error;

                $insertStmt->close();
                $usersStmt->close();

                throw new RuntimeException(
                    $error ?: "Failed to create notification"
                );
            }

            $createdCount++;
        }

        $insertStmt->close();
        $usersStmt->close();
    }

    /*
    |--------------------------------------------------------------------------
    | SELECTED USER
    |--------------------------------------------------------------------------
    */

    elseif ($target === "selected_user") {

        if ($recipientId <= 0) {
            throw new RuntimeException(
                "Selected user ID is required"
            );
        }

        $checkStmt = $con->prepare(
            "SELECT user_id
             FROM userreg_tb
             WHERE user_id = ?
             LIMIT 1"
        );

        if (!$checkStmt) {
            throw new RuntimeException(
                "Failed to prepare user validation"
            );
        }

        $checkStmt->bind_param(
            "i",
            $recipientId
        );

        if (!$checkStmt->execute()) {

            $error = $checkStmt->error;

            $checkStmt->close();

            throw new RuntimeException(
                $error ?: "Failed to validate user"
            );
        }

        $result = $checkStmt->get_result();

        if ($result->num_rows === 0) {

            $checkStmt->close();

            throw new RuntimeException(
                "Selected user not found"
            );
        }

        $checkStmt->close();

        $insertStmt = $con->prepare(
            "INSERT INTO notifications
            (
                user_id,
                admin_id,
                title,
                message,
                type,
                is_read
            )
            VALUES (?, NULL, ?, ?, ?, 0)"
        );

        if (!$insertStmt) {
            throw new RuntimeException(
                "Failed to prepare notification insert"
            );
        }

        $insertStmt->bind_param(
            "isss",
            $recipientId,
            $title,
            $message,
            $type
        );

        if (!$insertStmt->execute()) {

            $error =
                $insertStmt->error;

            $insertStmt->close();

            throw new RuntimeException(
                $error ?: "Failed to create notification"
            );
        }

        $insertStmt->close();

        $createdCount = 1;
    }

    /*
    |--------------------------------------------------------------------------
    | ALL ADMINS
    |--------------------------------------------------------------------------
    */

    elseif ($target === "all_admins") {

        $adminsStmt = $con->prepare(
            "SELECT id
             FROM adminreg_tb
             ORDER BY id ASC"
        );

        if (!$adminsStmt) {
            throw new RuntimeException(
                "Failed to prepare admin query"
            );
        }

        if (!$adminsStmt->execute()) {

            $error = $adminsStmt->error;

            $adminsStmt->close();

            throw new RuntimeException(
                $error ?: "Failed to fetch admins"
            );
        }

        $result =
            $adminsStmt->get_result();

        $insertStmt = $con->prepare(
            "INSERT INTO notifications
            (
                user_id,
                admin_id,
                title,
                message,
                type,
                is_read
            )
            VALUES (NULL, ?, ?, ?, ?, 0)"
        );

        if (!$insertStmt) {

            $adminsStmt->close();

            throw new RuntimeException(
                "Failed to prepare notification insert"
            );
        }

        while (
            $admin = $result->fetch_assoc()
        ) {

            $targetAdminId =
                (int) ($admin["id"]);

            $insertStmt->bind_param(
                "isss",
                $targetAdminId,
                $title,
                $message,
                $type
            );

            if (!$insertStmt->execute()) {

                $error =
                    $insertStmt->error;

                $insertStmt->close();
                $adminsStmt->close();

                throw new RuntimeException(
                    $error ?: "Failed to create admin notification"
                );
            }

            $createdCount++;
        }

        $insertStmt->close();
        $adminsStmt->close();
    }

    /*
    |--------------------------------------------------------------------------
    | SELECTED ADMIN
    |--------------------------------------------------------------------------
    */

    elseif ($target === "selected_admin") {

        if ($recipientId <= 0) {
            throw new RuntimeException(
                "Selected admin ID is required"
            );
        }

        $checkStmt = $con->prepare(
            "SELECT id
             FROM adminreg_tb
             WHERE id = ?
             LIMIT 1"
        );

        if (!$checkStmt) {
            throw new RuntimeException(
                "Failed to prepare admin validation"
            );
        }

        $checkStmt->bind_param(
            "i",
            $recipientId
        );

        if (!$checkStmt->execute()) {

            $error = $checkStmt->error;

            $checkStmt->close();

            throw new RuntimeException(
                $error ?: "Failed to validate admin"
            );
        }

        $result =
            $checkStmt->get_result();

        if ($result->num_rows === 0) {

            $checkStmt->close();

            throw new RuntimeException(
                "Selected admin not found"
            );
        }

        $checkStmt->close();

        $insertStmt = $con->prepare(
            "INSERT INTO notifications
            (
                user_id,
                admin_id,
                title,
                message,
                type,
                is_read
            )
            VALUES (NULL, ?, ?, ?, ?, 0)"
        );

        if (!$insertStmt) {
            throw new RuntimeException(
                "Failed to prepare admin notification insert"
            );
        }

        $insertStmt->bind_param(
            "isss",
            $recipientId,
            $title,
            $message,
            $type
        );

        if (!$insertStmt->execute()) {

            $error =
                $insertStmt->error;

            $insertStmt->close();

            throw new RuntimeException(
                $error ?: "Failed to create admin notification"
            );
        }

        $insertStmt->close();

        $createdCount = 1;
    }

    if ($createdCount <= 0) {
        throw new RuntimeException(
            "No recipients found"
        );
    }

    $con->commit();

    response(
        true,
        "Notification fired successfully",
        [
            "notification_type" => $type,
            "target" => $target,
            "recipient_id" =>
                $recipientId > 0
                    ? $recipientId
                    : null,
            "sent_count" => $createdCount,
            "admin_id" => $adminId
        ],
        200
    );

} catch (Throwable $e) {

    $con->rollback();

    response(
        false,
        $e->getMessage(),
        [],
        500
    );
}