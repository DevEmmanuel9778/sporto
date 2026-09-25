<?php

declare(strict_types=1);

ini_set("display_errors", "0");
ini_set("log_errors", "1");
error_reporting(E_ALL);

// ======================================================
// HEADERS / CORS
// ======================================================
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Max-Age: 86400");

if (($_SERVER["REQUEST_METHOD"] ?? "") === "OPTIONS") {
    http_response_code(204);
    exit;
}

// ======================================================
// METHOD
// ======================================================
if (($_SERVER["REQUEST_METHOD"] ?? "") !== "POST") {
    http_response_code(405);

    echo json_encode([
        "status" => false,
        "message" => "Only POST method is allowed",
    ]);

    exit;
}

// ======================================================
// FILES
// ======================================================
require_once __DIR__ . "/connection.php";
require_once __DIR__ . "/vendor/autoload.php";

use Cloudinary\Cloudinary;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// ======================================================
// JWT SECRET
// SAME SECRET USED BY owner_auth_api.php
// ======================================================
$secretKey = getenv("JWT_SECRET");

if ($secretKey === false || trim($secretKey) === "") {
    http_response_code(500);

    echo json_encode([
        "status" => false,
        "message" => "JWT_SECRET environment variable is missing",
    ]);

    exit;
}

// ======================================================
// RESPONSE
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
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    exit;
}

// ======================================================
// BEARER TOKEN
// ======================================================
function getBearerToken(): ?string
{
    $authorization = null;

    if (function_exists("getallheaders")) {
        $headers = getallheaders();

        foreach ($headers as $key => $value) {
            if (strtolower((string) $key) === "authorization") {
                $authorization = (string) $value;
                break;
            }
        }
    }

    if (!$authorization) {
        $authorization = $_SERVER["HTTP_AUTHORIZATION"] ?? null;
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
        $decoded = JWT::decode(
            $token,
            new Key($secretKey, "HS256")
        );

        $payload = (array) $decoded;

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

        if (
            !in_array(
                $role,
                ["owner", "admin"],
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
// AUTH
// ======================================================
$user = authenticateOwner();

$role = (string) (
    $user["role"] ?? ""
);

$userId = (int) (
    $user["user_id"]
    ?? $user["id"]
    ?? 0
);

// ======================================================
// DATABASE CHECK
// ======================================================
if (!isset($con) || !($con instanceof mysqli)) {
    response(
        false,
        "Database connection failed",
        [],
        500
    );
}

// ======================================================
// TURF ID
// Multipart fields are available in $_POST
// ======================================================
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

// ======================================================
// VERIFY TURF
// ======================================================
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

    $check = $con->prepare(
        "SELECT turf_id
         FROM turf_tb
         WHERE turf_id = ?
         LIMIT 1"
    );

    if (!$check) {
        response(
            false,
            "Database query failed",
            [],
            500
        );
    }

    $check->bind_param(
        "i",
        $turfId
    );

    $check->execute();

    if ($check->get_result()->num_rows === 0) {
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

// ======================================================
// IMAGE CHECK
// ======================================================
if (!isset($_FILES["image"])) {
    response(
        false,
        "No image file received. Use field name: image",
        [],
        400
    );
}

$image = $_FILES["image"];

if (($image["error"] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
    response(
        false,
        "Image upload failed",
        [
            "upload_error" => $image["error"] ?? null,
        ],
        400
    );
}

// ======================================================
// FILE SIZE
// MAX 10 MB
// ======================================================
$maxFileSize = 10 * 1024 * 1024;

if ((int) $image["size"] > $maxFileSize) {
    response(
        false,
        "Image size must be less than 10 MB",
        [],
        400
    );
}

// ======================================================
// MIME TYPE
// ======================================================
$allowedTypes = [
    "image/jpeg",
    "image/png",
    "image/webp",
];

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
    $image["tmp_name"]
);

finfo_close($fileInfo);

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
        [],
        400
    );
}

// ======================================================
// CLOUDINARY CONFIG
// ======================================================
$cloudName = getenv("CLOUDINARY_CLOUD_NAME");
$apiKey = getenv("CLOUDINARY_API_KEY");
$apiSecret = getenv("CLOUDINARY_API_SECRET");

if (
    !$cloudName ||
    !$apiKey ||
    !$apiSecret
) {
    response(
        false,
        "Cloudinary configuration is missing",
        [],
        500
    );
}

// ======================================================
// CHECK EXISTING IMAGES
// First image becomes cover image
// ======================================================
$countStmt = $con->prepare(
    "SELECT COUNT(*) AS total
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

$countStmt->execute();

$countRow = $countStmt
    ->get_result()
    ->fetch_assoc();

$existingCount = (int) (
    $countRow["total"] ?? 0
);

$countStmt->close();

$isCover = $existingCount === 0 ? 1 : 0;

// ======================================================
// CLOUDINARY UPLOAD
// ======================================================
try {

    $cloudinary = new Cloudinary([
        "cloud" => [
            "cloud_name" => $cloudName,
            "api_key" => $apiKey,
            "api_secret" => $apiSecret,
        ],
    ]);

    $uploadResult = $cloudinary
        ->uploadApi()
        ->upload(
            $image["tmp_name"],
            [
                "folder" => "sporto/turfs/" . $turfId,
                "resource_type" => "image",
            ]
        );

    $imageUrl = (string) (
        $uploadResult["secure_url"] ?? ""
    );

    $publicId = (string) (
        $uploadResult["public_id"] ?? ""
    );

    if ($imageUrl === "") {
        response(
            false,
            "Cloudinary returned no image URL",
            [],
            500
        );
    }

    // ==================================================
    // SAVE IMAGE URL
    // ==================================================
    $insert = $con->prepare(
        "INSERT INTO turf_images
        (
            turf_id,
            image_url,
            is_cover
        )
        VALUES (?, ?, ?)"
    );

    if (!$insert) {
        response(
            false,
            "Failed to prepare image database insert",
            [],
            500
        );
    }

    $insert->bind_param(
        "isi",
        $turfId,
        $imageUrl,
        $isCover
    );

    if (!$insert->execute()) {
        $error = $insert->error;
        $insert->close();

        response(
            false,
            "Failed to save image",
            [
                "error" => $error,
            ],
            500
        );
    }

    $imageId = (int) $insert->insert_id;

    $insert->close();

    // ==================================================
    // SUCCESS
    // ==================================================
    response(
        true,
        "Turf image uploaded successfully",
        [
            "image_id" => $imageId,
            "turf_id" => $turfId,
            "image_url" => $imageUrl,
            "public_id" => $publicId,
            "is_cover" => $isCover === 1,
        ],
        201
    );

} catch (Throwable $e) {

    response(
        false,
        "Cloudinary upload failed",
        [
            "error" => $e->getMessage(),
        ],
        500
    );
}