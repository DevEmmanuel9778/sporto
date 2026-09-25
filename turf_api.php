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
    "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS"
);
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Max-Age: 86400");

// Browser preflight
if (($_SERVER["REQUEST_METHOD"] ?? "") === "OPTIONS") {
    http_response_code(204);
    exit;
}

// ======================================================
// REQUIRED FILES
// ======================================================
require_once __DIR__ . "/connection.php";
require_once __DIR__ . "/vendor/autoload.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// ======================================================
// JWT SECRET
// ======================================================
$secretKey = getenv("JWT_SECRET");

if ($secretKey === false || trim($secretKey) === "") {
    response(
        false,
        "JWT_SECRET environment variable is missing",
        [],
        500
    );
}

// ======================================================
// RESPONSE HELPER
// ======================================================
function response(
    bool $status,
    string $message,
    array $data = [],
    int $code = 200
): never {
    http_response_code($code);

    echo json_encode(
        [
            "status" => $status,
            "message" => $message,
            ...$data,
        ],
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
            if (strtolower((string) $key) === "authorization") {
                $authorization = (string) $value;
                break;
            }
        }
    }

    // Apache / Render fallback
    if (!$authorization) {
        $authorization =
            $_SERVER["HTTP_AUTHORIZATION"] ?? null;
    }

    // Additional Apache fallback
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
// AUTHENTICATION
// ======================================================
function authenticate(array $allowedRoles = []): array
{
    global $secretKey;

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

        // Only access tokens are allowed
        if (($payload["type"] ?? "") !== "access") {
            response(
                false,
                "Invalid access token",
                [],
                401
            );
        }

        $role = (string) (
            $payload["role"] ?? ""
        );

        // Check role permission
        if (
            $allowedRoles !== [] &&
            !in_array(
                $role,
                $allowedRoles,
                true
            )
        ) {
            response(
                false,
                "You do not have permission for this action",
                [],
                403
            );
        }

        // Get user ID from JWT
        $userId = (int) (
            $payload["user_id"]
            ?? $payload["id"]
            ?? 0
        );

        if ($userId <= 0) {
            response(
                false,
                "Invalid token user ID",
                [],
                401
            );
        }

        return $payload;

    } catch (Throwable $e) {
        response(
            false,
            "Invalid or expired token",
            [],
            401
        );
    }
}

// ======================================================
// INPUT DATA
// ======================================================
function inputData(): array
{
    $raw = file_get_contents("php://input");

    if (
        $raw !== false &&
        trim($raw) !== ""
    ) {
        $data = json_decode(
            $raw,
            true
        );

        if (is_array($data)) {
            return $data;
        }
    }

    return is_array($_POST)
        ? $_POST
        : [];
}

// ======================================================
// CONVERT TURF ROW TO API FORMAT
// ======================================================
function turfRow(
    array $row
): array {
    $imageUrl = null;

    if (
        isset($row["image"]) &&
        trim((string) $row["image"]) !== ""
    ) {
        $imageUrl = trim(
            (string) $row["image"]
        );
    }

    return [
        "turf_id" => (int) (
            $row["turf_id"] ?? 0
        ),

        "owner_id" => (int) (
            $row["owner_id"] ?? 0
        ),

        "turf_name" => (string) (
            $row["turf_name"] ?? ""
        ),

        "location" => (string) (
            $row["location"] ?? ""
        ),

        "price" => (float) (
            $row["price"] ?? 0
        ),

        "status" => (string) (
            $row["status"] ?? ""
        ),

        // Cover image from turf_images
        "image" => $imageUrl,

        // Compatibility field
        "image_url" => $imageUrl,
    ];
}

// ======================================================
// REQUEST METHOD
// ======================================================
$method = strtoupper(
    $_SERVER["REQUEST_METHOD"] ?? "GET"
);

// ======================================================
// GET TURFS
// ======================================================
if ($method === "GET") {

    // User / Owner / Admin can read turfs
    authenticate([
        "user",
        "owner",
        "admin",
    ]);

    $id = isset($_GET["turf_id"])
        ? (int) $_GET["turf_id"]
        : 0;

    try {

        // ==================================================
        // SINGLE TURF
        // ==================================================
        if ($id > 0) {

            $sql = "
                SELECT
                    turf_tb.turf_id,
                    turf_tb.owner_id,
                    turf_tb.turf_name,
                    turf_tb.location,
                    turf_tb.price,
                    turf_tb.status,

                    (
                        SELECT ti.image_url
                        FROM turf_images ti
                        WHERE ti.turf_id = turf_tb.turf_id
                        ORDER BY
                            ti.is_cover DESC,
                            ti.image_id ASC
                        LIMIT 1
                    ) AS image

                FROM turf_tb

                WHERE turf_tb.turf_id = ?

                LIMIT 1
            ";

            $stmt = $con->prepare($sql);

            if (!$stmt) {
                response(
                    false,
                    "Failed to prepare turf query",
                    [
                        "error" => $con->error,
                    ],
                    500
                );
            }

            $stmt->bind_param(
                "i",
                $id
            );

        // ==================================================
        // ALL TURFS
        // ==================================================
        } else {

            $sql = "
                SELECT
                    turf_tb.turf_id,
                    turf_tb.owner_id,
                    turf_tb.turf_name,
                    turf_tb.location,
                    turf_tb.price,
                    turf_tb.status,

                    (
                        SELECT ti.image_url
                        FROM turf_images ti
                        WHERE ti.turf_id = turf_tb.turf_id
                        ORDER BY
                            ti.is_cover DESC,
                            ti.image_id ASC
                        LIMIT 1
                    ) AS image

                FROM turf_tb

                WHERE turf_tb.status != 'deleted'

                ORDER BY turf_tb.turf_id DESC
            ";

            $stmt = $con->prepare($sql);

            if (!$stmt) {
                response(
                    false,
                    "Failed to prepare turf query",
                    [
                        "error" => $con->error,
                    ],
                    500
                );
            }
        }

        // ==================================================
        // EXECUTE QUERY
        // ==================================================
        if (!$stmt->execute()) {

            $error = $stmt->error;

            $stmt->close();

            response(
                false,
                "Failed to fetch turfs",
                [
                    "error" => $error,
                ],
                500
            );
        }

        // ==================================================
        // GET RESULT
        // ==================================================
        $result = $stmt->get_result();

        if (!$result) {

            $error = $stmt->error;

            $stmt->close();

            response(
                false,
                "Failed to read turf results",
                [
                    "error" => $error,
                ],
                500
            );
        }

        $turfs = [];

        while ($row = $result->fetch_assoc()) {
            $turfs[] = turfRow($row);
        }

        $stmt->close();

        // ==================================================
        // SINGLE TURF RESPONSE
        // ==================================================
        if ($id > 0) {

            if ($turfs === []) {
                response(
                    false,
                    "Turf not found",
                    [],
                    404
                );
            }

            $singleTurf = $turfs[0];

            response(
                true,
                "Turf fetched successfully",
                [
                    // Single object
                    "turf" => $singleTurf,

                    // Compatibility
                    "data" => $singleTurf,

                    // Compatibility with list-based Flutter parser
                    "turfs" => [
                        $singleTurf,
                    ],
                ]
            );
        }

        // ==================================================
        // ALL TURFS RESPONSE
        // ==================================================
        response(
            true,
            "Turfs fetched successfully",
            [
                "turfs" => $turfs,
            ]
        );

    } catch (Throwable $e) {

        response(
            false,
            "Turf GET request failed",
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
}

// ======================================================
// AUTH FOR WRITE ACTIONS
// ======================================================
$user = authenticate([
    "owner",
    "admin",
]);

$role = (string) (
    $user["role"] ?? ""
);

$userId = (int) (
    $user["user_id"]
    ?? $user["id"]
    ?? 0
);

$data = inputData();

// ======================================================
// POST - ADD TURF
// ======================================================
if ($method === "POST") {

    $turfName = trim(
        (string) (
            $data["turf_name"] ?? ""
        )
    );

    $location = trim(
        (string) (
            $data["location"] ?? ""
        )
    );

    $price = (float) (
        $data["price"] ?? 0
    );

    // Owner gets owner_id from JWT
    // Admin must provide owner_id
    $ownerId = $role === "owner"
        ? $userId
        : (int) (
            $data["owner_id"] ?? 0
        );

    $status = trim(
        (string) (
            $data["status"] ?? "active"
        )
    );

    // ==================================================
    // VALIDATION
    // ==================================================
    if ($turfName === "") {
        response(
            false,
            "Turf name is required",
            [],
            422
        );
    }

    if ($location === "") {
        response(
            false,
            "Location is required",
            [],
            422
        );
    }

    if ($price <= 0) {
        response(
            false,
            "Price must be greater than 0",
            [],
            422
        );
    }

    if ($ownerId <= 0) {
        response(
            false,
            "Valid owner_id is required",
            [],
            422
        );
    }

    $allowedStatuses = [
        "active",
        "inactive",
        "deleted",
    ];

    if (
        !in_array(
            $status,
            $allowedStatuses,
            true
        )
    ) {
        $status = "active";
    }

    // ==================================================
    // INSERT TURF
    // ==================================================
    $stmt = $con->prepare(
        "INSERT INTO turf_tb
        (
            owner_id,
            turf_name,
            location,
            price,
            status
        )
        VALUES (?, ?, ?, ?, ?)"
    );

    if (!$stmt) {
        response(
            false,
            "Failed to prepare turf insert",
            [
                "error" => $con->error,
            ],
            500
        );
    }

    $stmt->bind_param(
        "issds",
        $ownerId,
        $turfName,
        $location,
        $price,
        $status
    );

    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        response(
            false,
            "Failed to add turf",
            [
                "error" => $error,
            ],
            500
        );
    }

    $newId = (int) $stmt->insert_id;

    $stmt->close();

    response(
        true,
        "Turf added successfully",
        [
            "turf_id" => $newId,
        ],
        201
    );
}

// ======================================================
// PUT / PATCH - UPDATE TURF
// ======================================================
if (
    $method === "PUT" ||
    $method === "PATCH"
) {

    $turfId = (int) (
        $data["turf_id"] ?? 0
    );

    if ($turfId <= 0) {
        response(
            false,
            "turf_id is required",
            [],
            422
        );
    }

    // ==================================================
    // OWNER OWNERSHIP CHECK
    // ==================================================
    if ($role === "owner") {

        $check = $con->prepare(
            "SELECT turf_id
             FROM turf_tb
             WHERE turf_id = ?
             AND owner_id = ?
             LIMIT 1"
        );

        if (!$check) {
            response(
                false,
                "Database query failed",
                [
                    "error" => $con->error,
                ],
                500
            );
        }

        $check->bind_param(
            "ii",
            $turfId,
            $userId
        );

        if (!$check->execute()) {

            $error = $check->error;

            $check->close();

            response(
                false,
                "Failed to verify turf ownership",
                [
                    "error" => $error,
                ],
                500
            );
        }

        $result = $check->get_result();

        if ($result->num_rows === 0) {

            $check->close();

            response(
                false,
                "You can update only your own turf",
                [],
                403
            );
        }

        $check->close();
    }

    // ==================================================
    // BUILD UPDATE QUERY
    // ==================================================
    $fields = [];
    $types = "";
    $values = [];

    // Turf name
    if (
        array_key_exists(
            "turf_name",
            $data
        )
    ) {

        $name = trim(
            (string) $data["turf_name"]
        );

        if ($name === "") {
            response(
                false,
                "Turf name cannot be empty",
                [],
                422
            );
        }

        $fields[] = "turf_name = ?";
        $types .= "s";
        $values[] = $name;
    }

    // Location
    if (
        array_key_exists(
            "location",
            $data
        )
    ) {

        $locationValue = trim(
            (string) $data["location"]
        );

        if ($locationValue === "") {
            response(
                false,
                "Location cannot be empty",
                [],
                422
            );
        }

        $fields[] = "location = ?";
        $types .= "s";
        $values[] = $locationValue;
    }

    // Price
    if (
        array_key_exists(
            "price",
            $data
        )
    ) {

        $priceValue = (float) (
            $data["price"]
        );

        if ($priceValue <= 0) {
            response(
                false,
                "Price must be greater than 0",
                [],
                422
            );
        }

        $fields[] = "price = ?";
        $types .= "d";
        $values[] = $priceValue;
    }

    // Status
    if (
        array_key_exists(
            "status",
            $data
        )
    ) {

        $statusValue = trim(
            (string) $data["status"]
        );

        $allowedStatuses = [
            "active",
            "inactive",
            "deleted",
        ];

        if (
            !in_array(
                $statusValue,
                $allowedStatuses,
                true
            )
        ) {
            response(
                false,
                "Invalid turf status",
                [],
                422
            );
        }

        $fields[] = "status = ?";
        $types .= "s";
        $values[] = $statusValue;
    }

    // Admin can change owner
    if (
        $role === "admin" &&
        array_key_exists(
            "owner_id",
            $data
        )
    ) {

        $ownerValue = (int) (
            $data["owner_id"]
        );

        if ($ownerValue <= 0) {
            response(
                false,
                "Invalid owner_id",
                [],
                422
            );
        }

        $fields[] = "owner_id = ?";
        $types .= "i";
        $values[] = $ownerValue;
    }

    if ($fields === []) {
        response(
            false,
            "No fields to update",
            [],
            422
        );
    }

    // ==================================================
    // UPDATE SQL
    // ==================================================
    $sql =
        "UPDATE turf_tb SET "
        . implode(
            ", ",
            $fields
        )
        . " WHERE turf_id = ?";

    $types .= "i";
    $values[] = $turfId;

    $stmt = $con->prepare($sql);

    if (!$stmt) {
        response(
            false,
            "Failed to prepare turf update",
            [
                "error" => $con->error,
            ],
            500
        );
    }

    // mysqli bind_param requires references
    $bindReferences = [];
    $bindReferences[] = $types;

    foreach ($values as $key => $value) {
        $bindReferences[] = &$values[$key];
    }

    if (
        !call_user_func_array(
            [
                $stmt,
                "bind_param",
            ],
            $bindReferences
        )
    ) {

        $stmt->close();

        response(
            false,
            "Failed to bind turf update parameters",
            [],
            500
        );
    }

    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        response(
            false,
            "Failed to update turf",
            [
                "error" => $error,
            ],
            500
        );
    }

    $stmt->close();

    response(
        true,
        "Turf updated successfully"
    );
}

// ======================================================
// DELETE TURF
// ======================================================
if ($method === "DELETE") {

    $turfId = (int) (
        $data["turf_id"]
        ?? $_GET["turf_id"]
        ?? 0
    );

    if ($turfId <= 0) {
        response(
            false,
            "turf_id is required",
            [],
            422
        );
    }

    // ==================================================
    // OWNER OWNERSHIP CHECK
    // ==================================================
    if ($role === "owner") {

        $check = $con->prepare(
            "SELECT turf_id
             FROM turf_tb
             WHERE turf_id = ?
             AND owner_id = ?
             LIMIT 1"
        );

        if (!$check) {
            response(
                false,
                "Database query failed",
                [
                    "error" => $con->error,
                ],
                500
            );
        }

        $check->bind_param(
            "ii",
            $turfId,
            $userId
        );

        if (!$check->execute()) {

            $check->close();

            response(
                false,
                "Failed to verify turf ownership",
                [],
                500
            );
        }

        $result = $check->get_result();

        if ($result->num_rows === 0) {

            $check->close();

            response(
                false,
                "You can delete only your own turf",
                [],
                403
            );
        }

        $check->close();
    }

    // ==================================================
    // CHECK BOOKING HISTORY
    // ==================================================
    $bookingCheck = $con->prepare(
        "SELECT COUNT(*) AS total
         FROM bookings
         WHERE turf_id = ?"
    );

    if (!$bookingCheck) {
        response(
            false,
            "Could not check turf bookings",
            [
                "error" => $con->error,
            ],
            500
        );
    }

    $bookingCheck->bind_param(
        "i",
        $turfId
    );

    if (!$bookingCheck->execute()) {

        $error = $bookingCheck->error;

        $bookingCheck->close();

        response(
            false,
            "Failed to check turf booking history",
            [
                "error" => $error,
            ],
            500
        );
    }

    $bookingResult =
        $bookingCheck
            ->get_result()
            ->fetch_assoc();

    $bookingCount = (int) (
        $bookingResult["total"] ?? 0
    );

    $bookingCheck->close();

    // ==================================================
    // SOFT DELETE IF BOOKINGS EXIST
    // ==================================================
    if ($bookingCount > 0) {

        $stmt = $con->prepare(
            "UPDATE turf_tb
             SET status = 'deleted'
             WHERE turf_id = ?"
        );

        if (!$stmt) {
            response(
                false,
                "Failed to prepare turf delete",
                [
                    "error" => $con->error,
                ],
                500
            );
        }

        $stmt->bind_param(
            "i",
            $turfId
        );

        if (!$stmt->execute()) {

            $error = $stmt->error;

            $stmt->close();

            response(
                false,
                "Failed to mark turf as deleted",
                [
                    "error" => $error,
                ],
                500
            );
        }

        $stmt->close();

        response(
            true,
            "Turf marked as deleted because booking history exists"
        );
    }

    // ==================================================
    // HARD DELETE IF NO BOOKINGS
    // ==================================================
    $stmt = $con->prepare(
        "DELETE FROM turf_tb
         WHERE turf_id = ?"
    );

    if (!$stmt) {
        response(
            false,
            "Failed to prepare turf delete",
            [
                "error" => $con->error,
            ],
            500
        );
    }

    $stmt->bind_param(
        "i",
        $turfId
    );

    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        response(
            false,
            "Failed to delete turf",
            [
                "error" => $error,
            ],
            500
        );
    }

    $stmt->close();

    response(
        true,
        "Turf deleted successfully"
    );
}

// ======================================================
// UNSUPPORTED METHOD
// ======================================================
response(
    false,
    "Unsupported request method",
    [],
    405
);

?>

