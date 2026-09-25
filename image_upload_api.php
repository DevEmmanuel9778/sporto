<?php

declare(strict_types=1);

// ============================================================
// ERROR HANDLING
// ============================================================

ini_set("display_errors", "0");
ini_set("log_errors", "1");
error_reporting(E_ALL);

ob_start();

// ============================================================
// HEADERS / CORS
// ============================================================

header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Max-Age: 86400");

// Browser preflight
if (
    ($_SERVER["REQUEST_METHOD"] ?? "") === "OPTIONS"
) {
    http_response_code(204);
    exit;
}

// ============================================================
// RESPONSE HELPER
// ============================================================

function response(
    bool $status,
    string $message,
    array $data = [],
    int $code = 200
): never {
    if (ob_get_level() > 0) {
        ob_clean();
    }

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
// REQUEST METHOD
// ============================================================

$method = strtoupper(
    $_SERVER["REQUEST_METHOD"] ?? ""
);

if ($method !== "POST") {
    response(
        false,
        "Only POST method is allowed",
        [],
        405
    );
}

// ============================================================
// REQUIRED FILES
// ============================================================

require_once __DIR__ . "/connection.php";
require_once __DIR__ . "/vendor/autoload.php";

// ============================================================
// JWT SECRET
// Same JWT_SECRET used by owner_auth_api.php
// ============================================================

$secretKey = getenv("JWT_SECRET");

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
                $authorization = (string) $value;
                break;
            }
        }
    }

    // Fallback
    if (!$authorization) {
        $authorization =
            $_SERVER["HTTP_AUTHORIZATION"]
            ?? $_SERVER[
                "REDIRECT_HTTP_AUTHORIZATION"
            ]
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
// AUTHENTICATE OWNER / ADMIN
// ============================================================

function authenticateOwner(): array
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
        $decoded = \Firebase\JWT\JWT::decode(
            $token,
            new \Firebase\JWT\Key(
                $secretKey,
                "HS256"
            )
        );

        $payload = (array) $decoded;

        // Access token only
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

        $role = (string) (
            $payload["role"] ?? ""
        );

        if (
            !in_array(
                $role,
                [
                    "owner",
                    "admin",
                ],
                true
            )
        ) {
            response(
                false,
                "Only owner or admin can upload turf images",
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
            response(
                false,
                "Invalid user ID in token",
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

// ============================================================
// AUTH
// ============================================================

$user = authenticateOwner();

$role = (string) (
    $user["role"] ?? ""
);

$userId = (int) (
    $user["user_id"]
    ?? $user["id"]
    ?? 0
);

// ============================================================
// DATABASE
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

if ($con->connect_errno) {
    response(
        false,
        "Database connection failed",
        [],
        500
    );
}

$con->set_charset("utf8mb4");

// ============================================================
// TURF ID
// Multipart form field
// ============================================================

$turfId = (int) (
    $_POST["turf_id"] ?? 0
);

if ($turfId <= 0) {
    response(
        false,
        "turf_id is required",
        [],
        422
    );
}

// ============================================================
// VERIFY TURF OWNERSHIP
// ============================================================

if ($role === "owner") {

    $check = $con->prepare(
        "SELECT
            turf_id,
            owner_id,
            status
         FROM turf_tb
         WHERE turf_id = ?
           AND owner_id = ?
         LIMIT 1"
    );

    if (!$check) {
        response(
            false,
            "Failed to prepare turf ownership check",
            [],
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
            "You can upload images only for your own turf",
            [],
            403
        );
    }

    $check->close();
} else {

    // Admin can upload for any existing turf
    $check = $con->prepare(
        "SELECT
            turf_id
         FROM turf_tb
         WHERE turf_id = ?
         LIMIT 1"
    );

    if (!$check) {
        response(
            false,
            "Failed to prepare turf check",
            [],
            500
        );
    }

    $check->bind_param(
        "i",
        $turfId
    );

    if (!$check->execute()) {
        $check->close();

        response(
            false,
            "Failed to verify turf",
            [],
            500
        );
    }

    $result = $check->get_result();

    if ($result->num_rows === 0) {
        $check->close();

        response(
            false,
            "Turf not found",
            [],
            404
        );
    }

    $check->close();
}

// ============================================================
// IMAGE CHECK
// ============================================================

if (
    !isset($_FILES["image"])
) {
    response(
        false,
        "No image file received. Field name must be 'image'",
        [],
        400
    );
}

$image = $_FILES["image"];

// ============================================================
// UPLOAD ERROR CHECK
// ============================================================

$uploadError = (int) (
    $image["error"]
    ?? UPLOAD_ERR_NO_FILE
);

if ($uploadError !== UPLOAD_ERR_OK) {

    $errorMessage = match ($uploadError) {
        UPLOAD_ERR_INI_SIZE,
        UPLOAD_ERR_FORM_SIZE =>
            "Image file is too large",

        UPLOAD_ERR_PARTIAL =>
            "Image upload was incomplete",

        UPLOAD_ERR_NO_FILE =>
            "No image file was uploaded",

        UPLOAD_ERR_NO_TMP_DIR =>
            "Server temporary folder is missing",

        UPLOAD_ERR_CANT_WRITE =>
            "Server could not save uploaded file",

        UPLOAD_ERR_EXTENSION =>
            "Image upload was stopped by a server extension",

        default =>
            "Unknown image upload error",
    };

    response(
        false,
        $errorMessage,
        [
            "upload_error" =>
                $uploadError,
        ],
        400
    );
}

// ============================================================
// FILE VALIDATION
// ============================================================

$tmpFile = (string) (
    $image["tmp_name"] ?? ""
);

$fileSize = (int) (
    $image["size"] ?? 0
);

if (
    $tmpFile === "" ||
    !is_uploaded_file($tmpFile)
) {
    response(
        false,
        "Invalid uploaded image",
        [],
        400
    );
}

// Maximum 10 MB
$maxFileSize =
    10 * 1024 * 1024;

if ($fileSize <= 0) {
    response(
        false,
        "Uploaded image is empty",
        [],
        400
    );
}

if ($fileSize > $maxFileSize) {
    response(
        false,
        "Image size must be less than 10 MB",
        [],
        400
    );
}

// ============================================================
// MIME TYPE
// ============================================================

$fileInfo = finfo_open(
    FILEINFO_MIME_TYPE
);

if ($fileInfo === false) {
    response(
        false,
        "Could not inspect image file",
        [],
        500
    );
}

$mimeType = finfo_file(
    $fileInfo,
    $tmpFile
);

finfo_close(
    $fileInfo
);

$allowedTypes = [
    "image/jpeg",
    "image/png",
    "image/webp",
];

if (
    !in_array(
        $mimeType,
        $allowedTypes,
        true
    )
) {
    response(
        false,
        "Only JPG, PNG and WEBP images are allowed",
        [
            "mime_type" => $mimeType,
        ],
        400
    );
}

// ============================================================
// CLOUDINARY CONFIG
// ============================================================

$cloudName =
    getenv("CLOUDINARY_CLOUD_NAME");

$apiKey =
    getenv("CLOUDINARY_API_KEY");

$apiSecret =
    getenv("CLOUDINARY_API_SECRET");

if (
    $cloudName === false ||
    trim($cloudName) === "" ||
    $apiKey === false ||
    trim($apiKey) === "" ||
    $apiSecret === false ||
    trim($apiSecret) === ""
) {
    response(
        false,
        "Cloudinary configuration is missing",
        [],
        500
    );
}

// ============================================================
// CHECK EXISTING TURF IMAGES
// First image = cover image
// ============================================================

$countStmt = $con->prepare(
    "SELECT
        COUNT(*) AS total
     FROM turf_images
     WHERE turf_id = ?"
);

if (!$countStmt) {
    response(
        false,
        "Failed to check existing turf images",
        [],
        500
    );
}

$countStmt->bind_param(
    "i",
    $turfId
);

if (!$countStmt->execute()) {
    $countStmt->close();

    response(
        false,
        "Failed to check existing turf images",
        [],
        500
    );
}

$countRow =
    $countStmt
        ->get_result()
        ->fetch_assoc();

$countStmt->close();

$existingImageCount =
    (int) (
        $countRow["total"] ?? 0
    );

// First image becomes cover
$isCover =
    $existingImageCount === 0
        ? 1
        : 0;

// ============================================================
// CLOUDINARY UPLOAD
// ============================================================

try {

    $cloudinary =
        new \Cloudinary\Cloudinary([
            "cloud" => [
                "cloud_name" =>
                    $cloudName,
                "api_key" =>
                    $apiKey,
                "api_secret" =>
                    $apiSecret,
            ],
        ]);

    $uploadResult =
        $cloudinary
            ->uploadApi()
            ->upload(
                $tmpFile,
                [
                    "folder" =>
                        "sporto/turfs/"
                        . $turfId,

                    "resource_type" =>
                        "image",
                ]
            );

    $imageUrl =
        (string) (
            $uploadResult[
                "secure_url"
            ] ?? ""
        );

    $publicId =
        (string) (
            $uploadResult[
                "public_id"
            ] ?? ""
        );

    if ($imageUrl === "") {
        response(
            false,
            "Cloudinary did not return an image URL",
            [],
            500
        );
    }

    // ========================================================
    // DATABASE TRANSACTION
    // ========================================================

    $con->begin_transaction();

    try {

        // If this is the first image,
        // make sure it is the only cover.
        if ($isCover === 1) {

            $resetCover =
                $con->prepare(
                    "UPDATE turf_images
                     SET is_cover = 0
                     WHERE turf_id = ?"
                );

            if (!$resetCover) {
                throw new RuntimeException(
                    "Failed to prepare cover reset"
                );
            }

            $resetCover->bind_param(
                "i",
                $turfId
            );

            if (
                !$resetCover->execute()
            ) {
                $resetCover->close();

                throw new RuntimeException(
                    "Failed to reset existing cover image"
                );
            }

            $resetCover->close();
        }

        // ====================================================
        // SAVE URL IN turf_images
        // ====================================================

        $insert =
            $con->prepare(
                "INSERT INTO turf_images
                (
                    turf_id,
                    image_url,
                    is_cover
                )
                VALUES (?, ?, ?)"
            );

        if (!$insert) {
            throw new RuntimeException(
                "Failed to prepare image database insert"
            );
        }

        $insert->bind_param(
            "isi",
            $turfId,
            $imageUrl,
            $isCover
        );

        if (!$insert->execute()) {
            $error =
                $insert->error;

            $insert->close();

            throw new RuntimeException(
                "Failed to save image: "
                . $error
            );
        }

        $imageId =
            (int) $insert->insert_id;

        $insert->close();

        $con->commit();

    } catch (Throwable $e) {

        $con->rollback();

        throw $e;
    }

    // ========================================================
    // SUCCESS
    // ========================================================

    response(
        true,
        "Turf cover image uploaded successfully",
        [
            "image_id" =>
                $imageId,

            "turf_id" =>
                $turfId,

            "image_url" =>
                $imageUrl,

            "public_id" =>
                $publicId,

            "is_cover" =>
                $isCover === 1,
        ],
        201
    );

} catch (Throwable $e) {

    response(
        false,
        "Cloudinary upload failed",
        [
            "error" =>
                $e->getMessage(),
        ],
        500
    );
}