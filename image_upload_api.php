<?php

header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);

    echo json_encode([
        "success" => false,
        "message" => "Only POST method is allowed."
    ]);

    exit;
}

/*
|--------------------------------------------------------------------------
| Composer Autoload
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/vendor/autoload.php';

use Cloudinary\Cloudinary;

/*
|--------------------------------------------------------------------------
| Cloudinary Configuration
|--------------------------------------------------------------------------
*/

$cloudName = getenv('CLOUDINARY_CLOUD_NAME');
$apiKey = getenv('CLOUDINARY_API_KEY');
$apiSecret = getenv('CLOUDINARY_API_SECRET');

if (!$cloudName || !$apiKey || !$apiSecret) {
    http_response_code(500);

    echo json_encode([
        "success" => false,
        "message" => "Cloudinary configuration is missing."
    ]);

    exit;
}

/*
|--------------------------------------------------------------------------
| Check Image
|--------------------------------------------------------------------------
*/

if (!isset($_FILES['image'])) {
    http_response_code(400);

    echo json_encode([
        "success" => false,
        "message" => "No image file received. Use field name: image"
    ]);

    exit;
}

$image = $_FILES['image'];

/*
|--------------------------------------------------------------------------
| Upload Error Check
|--------------------------------------------------------------------------
*/

if ($image['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);

    echo json_encode([
        "success" => false,
        "message" => "Image upload failed.",
        "upload_error" => $image['error']
    ]);

    exit;
}

/*
|--------------------------------------------------------------------------
| File Size Validation
|--------------------------------------------------------------------------
| Maximum: 10 MB
|--------------------------------------------------------------------------
*/

$maxFileSize = 10 * 1024 * 1024;

if ($image['size'] > $maxFileSize) {
    http_response_code(400);

    echo json_encode([
        "success" => false,
        "message" => "Image size must be less than 10 MB."
    ]);

    exit;
}

/*
|--------------------------------------------------------------------------
| MIME Type Validation
|--------------------------------------------------------------------------
*/

$allowedTypes = [
    'image/jpeg',
    'image/png',
    'image/webp'
];

$fileInfo = finfo_open(FILEINFO_MIME_TYPE);
$mimeType = finfo_file($fileInfo, $image['tmp_name']);
finfo_close($fileInfo);

if (!in_array($mimeType, $allowedTypes, true)) {
    http_response_code(400);

    echo json_encode([
        "success" => false,
        "message" => "Only JPG, PNG and WEBP images are allowed."
    ]);

    exit;
}

/*
|--------------------------------------------------------------------------
| Cloudinary Upload
|--------------------------------------------------------------------------
*/

try {

    $cloudinary = new Cloudinary([
        'cloud' => [
            'cloud_name' => $cloudName,
            'api_key' => $apiKey,
            'api_secret' => $apiSecret,
        ],
    ]);

    $result = $cloudinary
        ->uploadApi()
        ->upload(
            $image['tmp_name'],
            [
                'folder' => 'sporto',
                'resource_type' => 'image'
            ]
        );

    /*
    |--------------------------------------------------------------------------
    | Success Response
    |--------------------------------------------------------------------------
    */

    echo json_encode([
        "success" => true,
        "message" => "Image uploaded successfully.",
        "data" => [
            "url" => $result['secure_url'] ?? null,
            "public_id" => $result['public_id'] ?? null,
            "format" => $result['format'] ?? null,
            "width" => $result['width'] ?? null,
            "height" => $result['height'] ?? null
        ]
    ]);

} catch (Throwable $e) {

    http_response_code(500);

    echo json_encode([
        "success" => false,
        "message" => "Cloudinary upload failed.",
        "error" => $e->getMessage()
    ]);
}