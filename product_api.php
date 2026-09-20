<?php

declare(strict_types=1);

header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require_once __DIR__ . "/connection.php";
require_once __DIR__ . "/config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;


/*
|--------------------------------------------------------------------------
| OPTIONS
|--------------------------------------------------------------------------
*/

if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(200);
    exit;
}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

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
            ...$data
        ],
        JSON_UNESCAPED_UNICODE
    );

    exit;
}


/*
|--------------------------------------------------------------------------
| BEARER TOKEN
|--------------------------------------------------------------------------
*/

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


/*
|--------------------------------------------------------------------------
| AUTHENTICATION
|--------------------------------------------------------------------------
*/

function authenticate(array $allowedRoles): array
{
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


        if (
            ($payload["type"] ?? "") !== "access"
        ) {

            response(
                false,
                "Invalid access token",
                [],
                401
            );
        }


        $role = $payload["role"] ?? "";


        if (
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


/*
|--------------------------------------------------------------------------
| INPUT DATA
|--------------------------------------------------------------------------
*/

function inputData(): array
{
    $raw = file_get_contents(
        "php://input"
    );

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

    return $_POST;
}


/*
|--------------------------------------------------------------------------
| REQUEST
|--------------------------------------------------------------------------
*/

$method = $_SERVER["REQUEST_METHOD"];


/*
|--------------------------------------------------------------------------
| GET PRODUCTS
|--------------------------------------------------------------------------
|
| USER / OWNER / ADMIN can view products.
|
*/

if ($method === "GET") {

    authenticate([
        "user",
        "owner",
        "admin"
    ]);


    $productId = (int) (
        $_GET["product_id"] ?? 0
    );


    /*
    |--------------------------------------------------------------------------
    | SINGLE PRODUCT
    |--------------------------------------------------------------------------
    */

    if ($productId > 0) {

        $stmt = $con->prepare(
            "SELECT
                product_id,
                name,
                category,
                price,
                stock,
                image,
                status
             FROM products
             WHERE product_id = ?
             AND status != 'deleted'
             LIMIT 1"
        );


        if (!$stmt) {

            response(
                false,
                "Database query failed",
                [],
                500
            );
        }


        $stmt->bind_param(
            "i",
            $productId
        );
    }


    /*
    |--------------------------------------------------------------------------
    | ALL PRODUCTS
    |--------------------------------------------------------------------------
    */

    else {

        $stmt = $con->prepare(
            "SELECT
                product_id,
                name,
                category,
                price,
                stock,
                image,
                status
             FROM products
             WHERE status != 'deleted'
             ORDER BY product_id DESC"
        );


        if (!$stmt) {

            response(
                false,
                "Database query failed",
                [],
                500
            );
        }
    }


    /*
    |--------------------------------------------------------------------------
    | EXECUTE
    |--------------------------------------------------------------------------
    */

    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        response(
            false,
            "Failed to fetch products",
            [
                "error" => $error
            ],
            500
        );
    }


    $result = $stmt->get_result();

    $products = [];


    while (
        $row = $result->fetch_assoc()
    ) {

        $products[] = [

            "product_id" => (int) $row["product_id"],

            "name" => $row["name"],

            "category" => $row["category"],

            "price" => (float) $row["price"],

            "stock" => (int) $row["stock"],

            /*
            | Cloudinary URL
            */
            "image" => $row["image"] ?: null,

            "status" => $row["status"]
        ];
    }


    $stmt->close();


    response(
        true,
        "Products fetched successfully",
        [
            "products" => $products
        ]
    );
}


/*
|--------------------------------------------------------------------------
| ADMIN AUTHENTICATION
|--------------------------------------------------------------------------
|
| Only admin can add/update/delete products.
|
*/

$user = authenticate([
    "admin"
]);

$data = inputData();


/*
|--------------------------------------------------------------------------
| ADD PRODUCT
|--------------------------------------------------------------------------
*/

if ($method === "POST") {

    $name = trim(
        $data["name"] ?? ""
    );

    $category = trim(
        $data["category"] ?? ""
    );

    $price = (float) (
        $data["price"] ?? 0
    );

    $stock = (int) (
        $data["stock"] ?? 0
    );

    /*
    | Cloudinary secure_url
    */
    $image = trim(
        $data["image"] ?? ""
    );

    $status = trim(
        $data["status"] ?? "active"
    );


    /*
    |--------------------------------------------------------------------------
    | VALIDATION
    |--------------------------------------------------------------------------
    */

    if (
        $name === "" ||
        $category === "" ||
        $price <= 0 ||
        $stock < 0
    ) {

        response(
            false,
            "name, category, price and valid stock are required",
            [],
            422
        );
    }


    /*
    |--------------------------------------------------------------------------
    | INSERT
    |--------------------------------------------------------------------------
    */

    $stmt = $con->prepare(
        "INSERT INTO products
        (
            name,
            category,
            price,
            stock,
            image,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?)"
    );


    if (!$stmt) {

        response(
            false,
            "Failed to prepare product insert",
            [],
            500
        );
    }


    $stmt->bind_param(
        "ssdiss",
        $name,
        $category,
        $price,
        $stock,
        $image,
        $status
    );


    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        response(
            false,
            "Failed to add product",
            [
                "error" => $error
            ],
            500
        );
    }


    $productId = $stmt->insert_id;

    $stmt->close();


    response(
        true,
        "Product added successfully",
        [
            "product_id" => $productId,
            "image" => $image !== ""
                ? $image
                : null
        ],
        201
    );
}


/*
|--------------------------------------------------------------------------
| UPDATE PRODUCT
|--------------------------------------------------------------------------
*/

if (
    $method === "PUT" ||
    $method === "PATCH"
) {

    $productId = (int) (
        $data["product_id"] ?? 0
    );


    if ($productId <= 0) {

        response(
            false,
            "product_id is required",
            [],
            422
        );
    }


    $fields = [];

    $types = "";

    $values = [];


    /*
    | NAME
    */

    if (
        array_key_exists(
            "name",
            $data
        )
    ) {

        $fields[] = "name = ?";

        $types .= "s";

        $values[] = trim(
            (string) $data["name"]
        );
    }


    /*
    | CATEGORY
    */

    if (
        array_key_exists(
            "category",
            $data
        )
    ) {

        $fields[] = "category = ?";

        $types .= "s";

        $values[] = trim(
            (string) $data["category"]
        );
    }


    /*
    | PRICE
    */

    if (
        array_key_exists(
            "price",
            $data
        )
    ) {

        $price = (float) $data["price"];


        if ($price <= 0) {

            response(
                false,
                "Price must be greater than 0",
                [],
                422
            );
        }


        $fields[] = "price = ?";

        $types .= "d";

        $values[] = $price;
    }


    /*
    | STOCK
    */

    if (
        array_key_exists(
            "stock",
            $data
        )
    ) {

        $stock = (int) $data["stock"];


        if ($stock < 0) {

            response(
                false,
                "Stock cannot be negative",
                [],
                422
            );
        }


        $fields[] = "stock = ?";

        $types .= "i";

        $values[] = $stock;
    }


    /*
    | PRODUCT IMAGE
    |--------------------------------------------------------------------------
    | Cloudinary secure_url is stored here.
    */

    if (
        array_key_exists(
            "image",
            $data
        )
    ) {

        $image = trim(
            (string) $data["image"]
        );

        $fields[] = "image = ?";

        $types .= "s";

        $values[] = $image;
    }


    /*
    | STATUS
    */

    if (
        array_key_exists(
            "status",
            $data
        )
    ) {

        $status = trim(
            (string) $data["status"]
        );

        $fields[] = "status = ?";

        $types .= "s";

        $values[] = $status;
    }


    /*
    |--------------------------------------------------------------------------
    | NO FIELDS
    |--------------------------------------------------------------------------
    */

    if ($fields === []) {

        response(
            false,
            "No fields to update",
            [],
            422
        );
    }


    /*
    |--------------------------------------------------------------------------
    | UPDATE QUERY
    |--------------------------------------------------------------------------
    */

    $sql =
        "UPDATE products
         SET "
        . implode(
            ", ",
            $fields
        )
        . " WHERE product_id = ?";


    $types .= "i";

    $values[] = $productId;


    $stmt = $con->prepare(
        $sql
    );


    if (!$stmt) {

        response(
            false,
            "Failed to prepare product update",
            [
                "error" => $con->error
            ],
            500
        );
    }


    $stmt->bind_param(
        $types,
        ...$values
    );


    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        response(
            false,
            "Failed to update product",
            [
                "error" => $error
            ],
            500
        );
    }


    $stmt->close();


    response(
        true,
        "Product updated successfully"
    );
}


/*
|--------------------------------------------------------------------------
| DELETE PRODUCT
|--------------------------------------------------------------------------
*/

if ($method === "DELETE") {

    $productId = (int) (
        $data["product_id"]
        ?? $_GET["product_id"]
        ?? 0
    );


    if ($productId <= 0) {

        response(
            false,
            "product_id is required",
            [],
            422
        );
    }


    /*
    |--------------------------------------------------------------------------
    | SOFT DELETE
    |--------------------------------------------------------------------------
    */

    $stmt = $con->prepare(
        "UPDATE products
         SET status = 'deleted'
         WHERE product_id = ?
         AND status != 'deleted'"
    );


    if (!$stmt) {

        response(
            false,
            "Failed to prepare product delete",
            [],
            500
        );
    }


    $stmt->bind_param(
        "i",
        $productId
    );


    if (!$stmt->execute()) {

        $error = $stmt->error;

        $stmt->close();

        response(
            false,
            "Failed to delete product",
            [
                "error" => $error
            ],
            500
        );
    }


    if (
        $stmt->affected_rows === 0
    ) {

        $stmt->close();

        response(
            false,
            "Product not found",
            [],
            404
        );
    }


    $stmt->close();


    response(
        true,
        "Product deleted successfully"
    );
}


/*
|--------------------------------------------------------------------------
| UNSUPPORTED METHOD
|--------------------------------------------------------------------------
*/

response(
    false,
    "Unsupported request method",
    [],
    405
);

?>