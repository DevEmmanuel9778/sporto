<?php
declare(strict_types=1);

ini_set('display_errors', '0');
error_reporting(E_ALL);
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Cloudinary\Cloudinary;

function sendResponse(
    bool $status,
    string $message,
    array $extra = [],
    int $code = 200
): never {
    http_response_code($code);

    echo json_encode([
        'status' => $status,
        'message' => $message,
        ...$extra,
    ], JSON_UNESCAPED_SLASHES);

    exit;
}

// Only POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse(false, 'Only POST is allowed', [], 405);
}

// Get admin access token
$authorization = $_SERVER['HTTP_AUTHORIZATION']
    ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
    ?? '';

if ($authorization === '' && function_exists('getallheaders')) {
    foreach (getallheaders() as $key => $value) {
        if (strcasecmp($key, 'Authorization') === 0) {
            $authorization = $value;
            break;
        }
    }
}

if (!preg_match('/^Bearer\s+(.+)$/i', trim($authorization), $matches)) {
    sendResponse(false, 'Authorization token is required', [], 401);
}

$secret = getenv('JWT_SECRET');

if (!$secret) {
    sendResponse(false, 'JWT configuration missing', [], 500);
}

try {
    $payload = (array) JWT::decode(
        trim($matches[1]),
        new Key($secret, 'HS256')
    );
} catch (Throwable $e) {
    sendResponse(false, 'Invalid or expired token', [], 401);
}

if (($payload['type'] ?? '') !== 'access') {
    sendResponse(false, 'Invalid access token', [], 401);
}

if (($payload['role'] ?? '') !== 'admin') {
    sendResponse(
        false,
        'Only admin can upload product images',
        [],
        403
    );
}

// Validate uploaded image
if (!isset($_FILES['image'])) {
    sendResponse(false, 'Image is required', [], 422);
}

$image = $_FILES['image'];

if ($image['error'] !== UPLOAD_ERR_OK) {
    sendResponse(false, 'Image upload failed', [], 400);
}

if (
    !is_uploaded_file($image['tmp_name']) ||
    $image['size'] <= 0 ||
    $image['size'] > 10 * 1024 * 1024
) {
    sendResponse(false, 'Invalid image or image exceeds 10 MB', [], 422);
}

$mime = (new finfo(FILEINFO_MIME_TYPE))
    ->file($image['tmp_name']);

if (!in_array($mime, [
    'image/jpeg',
    'image/png',
    'image/webp',
], true)) {
    sendResponse(false, 'Only JPG, PNG and WEBP are allowed', [], 422);
}

// Cloudinary configuration
$cloudName = getenv('CLOUDINARY_CLOUD_NAME');
$apiKey = getenv('CLOUDINARY_API_KEY');
$apiSecret = getenv('CLOUDINARY_API_SECRET');

if (!$cloudName || !$apiKey || !$apiSecret) {
    sendResponse(false, 'Cloudinary configuration missing', [], 500);
}

try {
    $cloudinary = new Cloudinary([
        'cloud' => [
            'cloud_name' => $cloudName,
            'api_key' => $apiKey,
            'api_secret' => $apiSecret,
        ],
    ]);

    $result = $cloudinary->uploadApi()->upload(
        $image['tmp_name'],
        [
            'folder' => 'sporto/products',
            'resource_type' => 'image',
        ]
    );

    $imageUrl = (string) ($result['secure_url'] ?? '');

    if ($imageUrl === '') {
        sendResponse(false, 'Cloudinary returned no image URL', [], 500);
    }

    sendResponse(
        true,
        'Product image uploaded successfully',
        [
            'image_url' => $imageUrl,
            'secure_url' => $imageUrl,
            'public_id' => $result['public_id'] ?? null,
        ],
        201
    );

} catch (Throwable $e) {
    error_log('Product image upload failed: ' . $e->getMessage());

    sendResponse(false, 'Cloudinary upload failed', [], 500);
}