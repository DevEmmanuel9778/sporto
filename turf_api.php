<?php

// ============================================================
// SPORTO - TURF API
// Owner / Admin
// GET    -> User / Owner / Admin
// POST   -> Owner / Admin
// PUT    -> Owner / Admin
// PATCH  -> Owner / Admin
// DELETE -> Owner / Admin
// ============================================================

header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Max-Age: 86400");

// ============================================================
// OPTIONS
// ============================================================

if (
    ($_SERVER["REQUEST_METHOD"] ?? "") === "OPTIONS"
) {
    http_response_code(204);
    exit;
}

// ============================================================
// REQUIRED FILES
// ============================================================

require_once "../connection.php";
require_once "../config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// ============================================================
// RESPONSE
// ============================================================

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
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

// ============================================================
// BEARER TOKEN
// ============================================================

function getBearerToken(): ?string
{
    $authorization = null;

    // Apache / Render
    if (function_exists("getallheaders")) {

        $headers = getallheaders();

        foreach ($headers as $key => $value) {

            if (
                strtolower((string) $key)
                === "authorization"
            ) {
                $authorization =
                    (string) $value;

                break;
            }
        }
    }

    // Fallback
    if (!$authorization) {

        $authorization =
            $_SERVER["HTTP_AUTHORIZATION"]
            ?? $_SERVER["REDIRECT_HTTP_AUTHORIZATION"]
            ?? null;
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

// ============================================================
// AUTHENTICATION
// ============================================================

function authenticate(
    array $allowedRoles = []
): array {

    global $secret_key;

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
            new Key(
                $secret_key,
                "HS256"
            )
        );

        $payload = (array) $decoded;

        // Only access token allowed
        if (
            ($payload["type"] ?? "")
            !== "access"
        ) {

            response(
                false,
                "Invalid access token",
                [],
                401
            );
        }

        $role = strtolower(
            (string) (
                $payload["role"] ?? ""
            )
        );

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

        $payload["role"] = $role;

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

// ============================================================
// INPUT DATA
// ============================================================

function inputData(): array
{
    $raw = file_get_contents(
        "php://input"
    );

    if (
        $raw !== false &&
        trim($raw) !== ""
    ) {

        $decoded =
            json_decode(
                $raw,
                true
            );

        if (
            is_array($decoded)
        ) {
            return $decoded;
        }
    }

    return $_POST;
}

// ============================================================
// DATABASE CHECK
// ============================================================

if (
    !isset($con) ||
    !($con instanceof mysqli)
) {

    response(
        false,
        "Database connection failed",
        [],
        500
    );
}

if (
    $con->connect_errno
) {

    response(
        false,
        "Database connection failed",
        [],
        500
    );
}

$con->set_charset("utf8mb4");

// ============================================================
// TURF FORMATTER
// ============================================================

function formatTurf(
    array $row
): array {

    $facilities = [];

    if (
        isset($row["facilities"])
    ) {

        if (
            is_array(
                $row["facilities"]
            )
        ) {

            $facilities =
                array_values(
                    $row["facilities"]
                );

        } elseif (
            is_string(
                $row["facilities"]
            ) &&
            trim(
                $row["facilities"]
            ) !== ""
        ) {

            $decoded =
                json_decode(
                    $row["facilities"],
                    true
                );

            if (
                is_array($decoded)
            ) {
                $facilities =
                    array_values($decoded);
            }
        }
    }

    $imageUrl = null;

    if (
        isset($row["image"]) &&
        trim(
            (string) $row["image"]
        ) !== ""
    ) {

        $imageUrl =
            trim(
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

        "description" => (string) (
            $row["description"] ?? ""
        ),

        "facilities" => $facilities,

        "opening_time" =>
            $row["opening_time"]
            ?? null,

        "closing_time" =>
            $row["closing_time"]
            ?? null,

        "slot_duration_minutes" =>
            isset(
                $row["slot_duration_minutes"]
            )
            ? (int) $row["slot_duration_minutes"]
            : null,

        "slot_price" =>
            isset(
                $row["slot_price"]
            )
            ? (float) $row["slot_price"]
            : null,

        // Cover image
        "image" => $imageUrl,

        // Compatibility with Flutter model
        "image_url" => $imageUrl,
    ];
}

// ============================================================
// REQUEST METHOD
// ============================================================

$method =
    strtoupper(
        $_SERVER["REQUEST_METHOD"]
        ?? ""
    );

// ============================================================
// GET TURFS
// User / Owner / Admin
// ============================================================

if ($method === "GET") {

    authenticate(
        [
            "user",
            "owner",
            "admin",
        ]
    );

    $turfId =
        isset($_GET["turf_id"])
        ? (int) $_GET["turf_id"]
        : 0;

    // ========================================================
    // SINGLE TURF
    // ========================================================

    if ($turfId > 0) {

        $stmt = $con->prepare(
            "
            SELECT
                t.turf_id,
                t.owner_id,
                t.turf_name,
                t.location,
                t.price,
                t.status,
                t.description,
                t.facilities,
                t.opening_time,
                t.closing_time,
                t.slot_duration_minutes,
                t.slot_price,

                (
                    SELECT ti.image_url
                    FROM turf_images ti
                    WHERE ti.turf_id = t.turf_id
                    ORDER BY
                        ti.is_cover DESC,
                        ti.image_id ASC
                    LIMIT 1
                ) AS image

            FROM turf_tb t

            WHERE t.turf_id = ?

            LIMIT 1
            "
        );

        if (!$stmt) {

            response(
                false,
                "Database query failed",
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

    // ========================================================
    // ALL TURFS
    // ========================================================

    } else {

        $stmt = $con->prepare(
            "
            SELECT
                t.turf_id,
                t.owner_id,
                t.turf_name,
                t.location,
                t.price,
                t.status,
                t.description,
                t.facilities,
                t.opening_time,
                t.closing_time,
                t.slot_duration_minutes,
                t.slot_price,

                (
                    SELECT ti.image_url
                    FROM turf_images ti
                    WHERE ti.turf_id = t.turf_id
                    ORDER BY
                        ti.is_cover DESC,
                        ti.image_id ASC
                    LIMIT 1
                ) AS image

            FROM turf_tb t

            WHERE t.status != 'deleted'

            ORDER BY
                t.turf_id DESC
            "
        );

        if (!$stmt) {

            response(
                false,
                "Database query failed",
                [
                    "error" => $con->error,
                ],
                500
            );
        }
    }

    // ========================================================
    // EXECUTE
    // ========================================================

    if (!$stmt->execute()) {

        $error =
            $stmt->error;

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

    $result =
        $stmt->get_result();

    $turfs = [];

    while (
        $row =
            $result->fetch_assoc()
    ) {

        $turfs[] =
            formatTurf($row);
    }

    $stmt->close();

    // ========================================================
    // SINGLE TURF RESPONSE
    // ========================================================

    if ($turfId > 0) {

        if (
            count($turfs) === 0
        ) {

            response(
                false,
                "Turf not found",
                [],
                404
            );
        }

        $turf =
            $turfs[0];

        response(
            true,
            "Turf fetched successfully",
            [
                "turf" => $turf,
                "data" => $turf,
                "turfs" => [
                    $turf,
                ],
            ]
        );
    }

    // ========================================================
    // ALL TURFS RESPONSE
    // ========================================================

    response(
        true,
        "Turfs fetched successfully",
        [
            "turfs" => $turfs,
        ]
    );
}

// ============================================================
// OWNER / ADMIN AUTH FOR WRITE OPERATIONS
// ============================================================

$user =
    authenticate(
        [
            "owner",
            "admin",
        ]
    );

$role =
    strtolower(
        (string) (
            $user["role"] ?? ""
        )
    );

$userId =
    (int) (
        $user["user_id"]
        ?? $user["id"]
        ?? 0
    );

$data =
    inputData();

// ============================================================
// POST - ADD TURF
// ============================================================

if ($method === "POST") {

    // ========================================================
    // BASIC FIELDS
    // ========================================================

    $turfName =
        trim(
            (string) (
                $data["turf_name"] ?? ""
            )
        );

    $location =
        trim(
            (string) (
                $data["location"] ?? ""
            )
        );

    $price =
        (float) (
            $data["price"] ?? 0
        );

    // ========================================================
    // OWNER ID
    // ========================================================

    $ownerId =
        $role === "owner"
        ? $userId
        : (int) (
            $data["owner_id"] ?? 0
        );

    // ========================================================
    // OPTIONAL FIELDS
    // ========================================================

    $description =
        trim(
            (string) (
                $data["description"] ?? ""
            )
        );

    $openingTime =
        trim(
            (string) (
                $data["opening_time"] ?? ""
            )
        );

    $closingTime =
        trim(
            (string) (
                $data["closing_time"] ?? ""
            )
        );

    $slotDurationMinutes =
        (int) (
            $data["slot_duration_minutes"]
            ?? 0
        );

    $slotPrice =
        (float) (
            $data["slot_price"]
            ?? 0
        );

    $status =
        trim(
            (string) (
                $data["status"]
                ?? "active"
            )
        );

    // ========================================================
    // FACILITIES
    // ========================================================

    $facilities =
        $data["facilities"]
        ?? [];

    if (
        !is_array($facilities)
    ) {
        $facilities = [];
    }

    $facilitiesJson =
        json_encode(
            array_values(
                $facilities
            ),
            JSON_UNESCAPED_UNICODE |
            JSON_UNESCAPED_SLASHES
        );

    if (
        $facilitiesJson === false
    ) {
        $facilitiesJson = "[]";
    }

    // ========================================================
    // VALIDATION
    // ========================================================

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
            "Valid owner ID is required",
            [],
            422
        );
    }

    if (
        $slotDurationMinutes <= 0
    ) {

        response(
            false,
            "Valid slot duration is required",
            [],
            422
        );
    }

    if ($slotPrice <= 0) {

        response(
            false,
            "Valid slot price is required",
            [],
            422
        );
    }

    // ========================================================
    // STATUS VALIDATION
    // ========================================================

    if (
        !in_array(
            $status,
            [
                "active",
                "inactive",
                "deleted",
            ],
            true
        )
    ) {
        $status = "active";
    }

    // ========================================================
    // INSERT TURF
    // ========================================================

    $stmt =
        $con->prepare(
            "
            INSERT INTO turf_tb
            (
                owner_id,
                turf_name,
                location,
                price,
                status,
                description,
                facilities,
                opening_time,
                closing_time,
                slot_duration_minutes,
                slot_price
            )
            VALUES
            (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            )
            "
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
        "issdsssssid",
        $ownerId,
        $turfName,
        $location,
        $price,
        $status,
        $description,
        $facilitiesJson,
        $openingTime,
        $closingTime,
        $slotDurationMinutes,
        $slotPrice
    );

    if (!$stmt->execute()) {

        $error =
            $stmt->error;

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

    $newId =
        (int) $stmt->insert_id;

    $stmt->close();

    // ========================================================
    // RESPONSE
    // ========================================================

    response(
        true,
        "Turf added successfully",
        [
            "turf_id" => $newId,
        ],
        201
    );
}

// ============================================================
// PUT / PATCH - UPDATE TURF
// ============================================================

if (
    $method === "PUT" ||
    $method === "PATCH"
) {

    $turfId =
        (int) (
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

    // ========================================================
    // OWNER OWNERSHIP
    // ========================================================

    if ($role === "owner") {

        $check =
            $con->prepare(
                "
                SELECT turf_id
                FROM turf_tb
                WHERE turf_id = ?
                  AND owner_id = ?
                LIMIT 1
                "
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

        if (
            $check
                ->get_result()
                ->num_rows === 0
        ) {

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

    // ========================================================
    // DYNAMIC UPDATE
    // ========================================================

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

        $fields[] =
            "turf_name = ?";

        $types .= "s";

        $values[] =
            trim(
                (string) $data["turf_name"]
            );
    }

    // Location
    if (
        array_key_exists(
            "location",
            $data
        )
    ) {

        $fields[] =
            "location = ?";

        $types .= "s";

        $values[] =
            trim(
                (string) $data["location"]
            );
    }

    // Price
    if (
        array_key_exists(
            "price",
            $data
        )
    ) {

        $newPrice =
            (float) $data["price"];

        if ($newPrice <= 0) {

            response(
                false,
                "Price must be greater than 0",
                [],
                422
            );
        }

        $fields[] =
            "price = ?";

        $types .= "d";

        $values[] =
            $newPrice;
    }

    // Status
    if (
        array_key_exists(
            "status",
            $data
        )
    ) {

        $newStatus =
            trim(
                (string) $data["status"]
            );

        if (
            !in_array(
                $newStatus,
                [
                    "active",
                    "inactive",
                    "deleted",
                ],
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

        $fields[] =
            "status = ?";

        $types .= "s";

        $values[] =
            $newStatus;
    }

    // Description
    if (
        array_key_exists(
            "description",
            $data
        )
    ) {

        $fields[] =
            "description = ?";

        $types .= "s";

        $values[] =
            trim(
                (string) $data["description"]
            );
    }

    // Facilities
    if (
        array_key_exists(
            "facilities",
            $data
        )
    ) {

        $newFacilities =
            $data["facilities"];

        if (
            !is_array(
                $newFacilities
            )
        ) {
            $newFacilities = [];
        }

        $newFacilitiesJson =
            json_encode(
                array_values(
                    $newFacilities
                ),
                JSON_UNESCAPED_UNICODE |
                JSON_UNESCAPED_SLASHES
            );

        if (
            $newFacilitiesJson === false
        ) {
            $newFacilitiesJson = "[]";
        }

        $fields[] =
            "facilities = ?";

        $types .= "s";

        $values[] =
            $newFacilitiesJson;
    }

    // Opening time
    if (
        array_key_exists(
            "opening_time",
            $data
        )
    ) {

        $fields[] =
            "opening_time = ?";

        $types .= "s";

        $values[] =
            trim(
                (string) $data["opening_time"]
            );
    }

    // Closing time
    if (
        array_key_exists(
            "closing_time",
            $data
        )
    ) {

        $fields[] =
            "closing_time = ?";

        $types .= "s";

        $values[] =
            trim(
                (string) $data["closing_time"]
            );
    }

    // Slot duration
    if (
        array_key_exists(
            "slot_duration_minutes",
            $data
        )
    ) {

        $duration =
            (int) $data[
                "slot_duration_minutes"
            ];

        if ($duration <= 0) {

            response(
                false,
                "Slot duration must be greater than 0",
                [],
                422
            );
        }

        $fields[] =
            "slot_duration_minutes = ?";

        $types .= "i";

        $values[] =
            $duration;
    }

    // Slot price
    if (
        array_key_exists(
            "slot_price",
            $data
        )
    ) {

        $newSlotPrice =
            (float) $data[
                "slot_price"
            ];

        if ($newSlotPrice <= 0) {

            response(
                false,
                "Slot price must be greater than 0",
                [],
                422
            );
        }

        $fields[] =
            "slot_price = ?";

        $types .= "d";

        $values[] =
            $newSlotPrice;
    }

    // Admin can change owner
    if (
        $role === "admin" &&
        array_key_exists(
            "owner_id",
            $data
        )
    ) {

        $newOwnerId =
            (int) $data[
                "owner_id"
            ];

        if ($newOwnerId <= 0) {

            response(
                false,
                "Valid owner ID is required",
                [],
                422
            );
        }

        $fields[] =
            "owner_id = ?";

        $types .= "i";

        $values[] =
            $newOwnerId;
    }

    // ========================================================
    // NO FIELDS
    // ========================================================

    if (
        count($fields) === 0
    ) {

        response(
            false,
            "No fields to update",
            [],
            422
        );
    }

    // ========================================================
    // BUILD UPDATE
    // ========================================================

    $sql =
        "UPDATE turf_tb SET "
        . implode(
            ", ",
            $fields
        )
        . " WHERE turf_id = ?";

    $types .= "i";

    $values[] =
        $turfId;

    $stmt =
        $con->prepare($sql);

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

    /*
     * mysqli::bind_param needs references.
     * Create a reference array safely.
     */
    $bindValues = [];

    $bindValues[] =
        $types;

    foreach (
        $values as $index => $value
    ) {
        $bindValues[] =
            &$values[$index];
    }

    if (
        !call_user_func_array(
            [
                $stmt,
                "bind_param",
            ],
            $bindValues
        )
    ) {

        $stmt->close();

        response(
            false,
            "Failed to bind turf update values",
            [],
            500
        );
    }

    if (!$stmt->execute()) {

        $error =
            $stmt->error;

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

    // ========================================================
    // RESPONSE
    // ========================================================

    response(
        true,
        "Turf updated successfully",
        [
            "turf_id" => $turfId,
        ]
    );
}

// ============================================================
// DELETE TURF
// ============================================================

if ($method === "DELETE") {

    $turfId =
        (int) (
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

    // ========================================================
    // OWNER OWNERSHIP
    // ========================================================

    if ($role === "owner") {

        $check =
            $con->prepare(
                "
                SELECT turf_id
                FROM turf_tb
                WHERE turf_id = ?
                  AND owner_id = ?
                LIMIT 1
                "
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

        if (
            $check
                ->get_result()
                ->num_rows === 0
        ) {

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

    // ========================================================
    // BOOKING HISTORY CHECK
    // ========================================================

    $bookingCheck =
        $con->prepare(
            "
            SELECT COUNT(*) AS total
            FROM bookings
            WHERE turf_id = ?
            "
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

        $error =
            $bookingCheck->error;

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

    $bookingRow =
        $bookingCheck
            ->get_result()
            ->fetch_assoc();

    $bookingCount =
        (int) (
            $bookingRow["total"]
            ?? 0
        );

    $bookingCheck->close();

    // ========================================================
    // SOFT DELETE IF BOOKINGS EXIST
    // ========================================================

    if ($bookingCount > 0) {

        $stmt =
            $con->prepare(
                "
                UPDATE turf_tb
                SET status = 'deleted'
                WHERE turf_id = ?
                "
            );

        if (!$stmt) {

            response(
                false,
                "Failed to prepare turf delete",
                [],
                500
            );
        }

        $stmt->bind_param(
            "i",
            $turfId
        );

        if (!$stmt->execute()) {

            $error =
                $stmt->error;

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
            "Turf marked as deleted because booking history exists",
            [
                "turf_id" => $turfId,
            ]
        );
    }

    // ========================================================
    // DELETE TURF SLOTS
    // ========================================================

    $deleteSlots =
        $con->prepare(
            "
            DELETE FROM turf_slots
            WHERE turf_id = ?
            "
        );

    if ($deleteSlots) {

        $deleteSlots->bind_param(
            "i",
            $turfId
        );

        $deleteSlots->execute();

        $deleteSlots->close();
    }

    // ========================================================
    // DELETE TURF IMAGES
    // ========================================================

    $deleteImages =
        $con->prepare(
            "
            DELETE FROM turf_images
            WHERE turf_id = ?
            "
        );

    if ($deleteImages) {

        $deleteImages->bind_param(
            "i",
            $turfId
        );

        $deleteImages->execute();

        $deleteImages->close();
    }

    // ========================================================
    // HARD DELETE TURF
    // ========================================================

    $stmt =
        $con->prepare(
            "
            DELETE FROM turf_tb
            WHERE turf_id = ?
            "
        );

    if (!$stmt) {

        response(
            false,
            "Failed to prepare turf delete",
            [],
            500
        );
    }

    $stmt->bind_param(
        "i",
        $turfId
    );

    if (!$stmt->execute()) {

        $error =
            $stmt->error;

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

    // ========================================================
    // RESPONSE
    // ========================================================

    response(
        true,
        "Turf deleted successfully",
        [
            "turf_id" => $turfId,
        ]
    );
}

// ============================================================
// UNSUPPORTED METHOD
// ============================================================

response(
    false,
    "Unsupported request method",
    [],
    405
);

?>