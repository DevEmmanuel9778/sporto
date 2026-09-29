<?php

/*
|--------------------------------------------------------------------------
| SPORTO PRODUCT API
|--------------------------------------------------------------------------
| GET    -> user / owner / admin
| POST   -> admin
| PUT    -> admin
| PATCH  -> admin
| DELETE -> admin
|--------------------------------------------------------------------------
*/

header("Content-Type: application/json; charset=UTF-8");
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");

header("Access-Control-Allow-Origin: *");
header(
    "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS"
);
header(
    "Access-Control-Allow-Headers: Content-Type, Authorization"
);


/*
|--------------------------------------------------------------------------
| GLOBAL RESPONSE FLAG
|--------------------------------------------------------------------------
*/

$responseSent = false;


/*
|--------------------------------------------------------------------------
| FORCE JSON RESPONSE FOR PHP ERRORS
|--------------------------------------------------------------------------
*/

function sendJsonResponse(
    $status,
    $message,
    $data = array(),
    $code = 200
) {
    global $responseSent;

    $responseSent = true;

    http_response_code($code);

    $payload = array(
        "status" => (bool) $status,
        "message" => (string) $message
    );

    if (is_array($data) && !empty($data)) {
        foreach ($data as $key => $value) {
            $payload[$key] = $value;
        }
    }

    $json = json_encode(
        $payload,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES |
        JSON_INVALID_UTF8_SUBSTITUTE
    );

    if ($json === false) {
        $json = json_encode(
            array(
                "status" => false,
                "message" => "Server could not create JSON response"
            )
        );
    }

    echo $json;

    exit;
}


/*
|--------------------------------------------------------------------------
| PHP WARNING / NOTICE HANDLER
|--------------------------------------------------------------------------
*/

set_error_handler(
    function (
        $severity,
        $message,
        $file,
        $line
    ) {
        if (!(error_reporting() & $severity)) {
            return false;
        }

        sendJsonResponse(
            false,
            "Server error",
            array(
                "error" => $message
            ),
            500
        );

        return true;
    }
);


/*
|--------------------------------------------------------------------------
| PHP EXCEPTION HANDLER
|--------------------------------------------------------------------------
*/

set_exception_handler(
    function ($exception) {

        sendJsonResponse(
            false,
            "Server exception",
            array(
                "error" => $exception->getMessage()
            ),
            500
        );
    }
);


/*
|--------------------------------------------------------------------------
| FATAL ERROR HANDLER
|--------------------------------------------------------------------------
*/

register_shutdown_function(
    function () {

        global $responseSent;

        if ($responseSent) {
            return;
        }

        $error = error_get_last();

        if ($error === null) {
            return;
        }

        $fatalTypes = array(
            E_ERROR,
            E_PARSE,
            E_CORE_ERROR,
            E_COMPILE_ERROR
        );

        if (in_array($error["type"], $fatalTypes, true)) {

            http_response_code(500);

            header(
                "Content-Type: application/json; charset=UTF-8"
            );

            echo json_encode(
                array(
                    "status" => false,
                    "message" => "Server fatal error",
                    "error" => $error["message"]
                ),
                JSON_UNESCAPED_UNICODE |
                JSON_UNESCAPED_SLASHES |
                JSON_INVALID_UTF8_SUBSTITUTE
            );
        }
    }
);


/*
|--------------------------------------------------------------------------
| CORS PREFLIGHT
|--------------------------------------------------------------------------
*/

if (
    isset($_SERVER["REQUEST_METHOD"]) &&
    $_SERVER["REQUEST_METHOD"] === "OPTIONS"
) {

    http_response_code(200);

    echo json_encode(
        array(
            "status" => true,
            "message" => "OK"
        ),
        JSON_UNESCAPED_UNICODE
    );

    exit;
}


/*
|--------------------------------------------------------------------------
| CONNECTION
|--------------------------------------------------------------------------
*/

require_once __DIR__ . "/connection.php";


/*
|--------------------------------------------------------------------------
| JWT CONFIG
|--------------------------------------------------------------------------
*/

require_once __DIR__ . "/config/jwt.php";


/*
|--------------------------------------------------------------------------
| JWT CLASSES
|--------------------------------------------------------------------------
*/

use Firebase\JWT\JWT;
use Firebase\JWT\Key;


/*
|--------------------------------------------------------------------------
| DATABASE CHECK
|--------------------------------------------------------------------------
*/

if (!isset($con) || !($con instanceof mysqli)) {

    sendJsonResponse(
        false,
        "Database connection is not available",
        array(),
        500
    );
}


/*
|--------------------------------------------------------------------------
| DATABASE CHARACTER SET
|--------------------------------------------------------------------------
*/

if (!$con->set_charset("utf8mb4")) {

    sendJsonResponse(
        false,
        "Failed to configure database connection",
        array(),
        500
    );
}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

function response(
    $status,
    $message,
    $data = array(),
    $code = 200
) {

    sendJsonResponse(
        $status,
        $message,
        $data,
        $code
    );
}


/*
|--------------------------------------------------------------------------
| GET BEARER TOKEN
|--------------------------------------------------------------------------
*/

function getBearerToken()
{
    $headers = array();

    if (function_exists("getallheaders")) {
        $headers = getallheaders();
    }

    $authorization =
        isset($headers["Authorization"])
            ? $headers["Authorization"]
            : (
                isset($headers["authorization"])
                    ? $headers["authorization"]
                    : (
                        isset($_SERVER["HTTP_AUTHORIZATION"])
                            ? $_SERVER["HTTP_AUTHORIZATION"]
                            : null
                    )
            );

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

function authenticate($allowedRoles)
{
    global $secret_key;

    if (
        !isset($secret_key) ||
        trim((string) $secret_key) === ""
    ) {

        response(
            false,
            "JWT configuration is missing",
            array(),
            500
        );
    }

    $token = getBearerToken();

    if (!$token) {

        response(
            false,
            "Authorization token is required",
            array(),
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

        /*
        | Access token only
        */
        if (
            !isset($payload["type"]) ||
            $payload["type"] !== "access"
        ) {

            response(
                false,
                "Invalid access token",
                array(),
                401
            );
        }

        $role =
            isset($payload["role"])
                ? (string) $payload["role"]
                : "";

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
                array(),
                403
            );
        }

        return $payload;

    } catch (Throwable $e) {

        response(
            false,
            "Invalid or expired token",
            array(),
            401
        );
    }
}


/*
|--------------------------------------------------------------------------
| INPUT DATA
|--------------------------------------------------------------------------
*/

function inputData()
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

        if (
            json_last_error() === JSON_ERROR_NONE &&
            is_array($decoded)
        ) {

            return $decoded;
        }
    }

    if (isset($_POST) && is_array($_POST)) {
        return $_POST;
    }

    return array();
}


/*
|--------------------------------------------------------------------------
| REQUEST METHOD
|--------------------------------------------------------------------------
*/

$method =
    isset($_SERVER["REQUEST_METHOD"])
        ? strtoupper(
            $_SERVER["REQUEST_METHOD"]
        )
        : "GET";


/*
|--------------------------------------------------------------------------
| GET PRODUCTS
|--------------------------------------------------------------------------
|
| user / owner / admin
|
*/

if ($method === "GET") {

    authenticate(
        array(
            "user",
            "owner",
            "admin"
        )
    );

    $productId =
        isset($_GET["product_id"])
            ? (int) $_GET["product_id"]
            : 0;


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
                array(
                    "error" => $con->error
                ),
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
                array(
                    "error" => $con->error
                ),
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
            array(
                "error" => $error
            ),
            500
        );
    }


    /*
    |--------------------------------------------------------------------------
    | RESULT
    |--------------------------------------------------------------------------
    */

    $result = $stmt->get_result();

    if (!$result) {

        $error = $stmt->error;

        $stmt->close();

        response(
            false,
            "Failed to read product results",
            array(
                "error" => $error
            ),
            500
        );
    }


    $products = array();


    while ($row = $result->fetch_assoc()) {

        $products[] = array(
            "product_id" => (int) $row["product_id"],
            "name" => isset($row["name"])
                ? (string) $row["name"]
                : "",
            "category" => isset($row["category"])
                ? (string) $row["category"]
                : "",
            "price" => isset($row["price"])
                ? (float) $row["price"]
                : 0,
            "stock" => isset($row["stock"])
                ? (int) $row["stock"]
                : 0,
            "image" =>
                isset($row["image"]) &&
                trim((string) $row["image"]) !== ""
                    ? (string) $row["image"]
                    : null,
            "status" => isset($row["status"])
                ? (string) $row["status"]
                : ""
        );
    }


    $stmt->close();


    /*
    |--------------------------------------------------------------------------
    | SUCCESS
    |--------------------------------------------------------------------------
    */

    response(
        true,
        "Products fetched successfully",
        array(
            "products" => $products
        ),
        200
    );
}


/*
|--------------------------------------------------------------------------
| ADMIN AUTHENTICATION
|--------------------------------------------------------------------------
*/

$adminPayload = authenticate(
    array("admin")
);


/*
|--------------------------------------------------------------------------
| REQUEST DATA
|--------------------------------------------------------------------------
*/

$data = inputData();


/*
|--------------------------------------------------------------------------
| ADD PRODUCT
|--------------------------------------------------------------------------
*/

if ($method === "POST") {

    $name =
        isset($data["name"])
            ? trim((string) $data["name"])
            : "";

    $category =
        isset($data["category"])
            ? trim((string) $data["category"])
            : "";

    $price =
        isset($data["price"])
            ? (float) $data["price"]
            : 0;

    $stock =
        isset($data["stock"])
            ? (int) $data["stock"]
            : 0;

    $image =
        isset($data["image"])
            ? trim((string) $data["image"])
            : "";

    $status =
        isset($data["status"])
            ? trim((string) $data["status"])
            : "available";


    if ($name === "") {

        response(
            false,
            "Product name is required",
            array(),
            422
        );
    }

    if ($category === "") {

        response(
            false,
            "Product category is required",
            array(),
            422
        );
    }

    if ($price <= 0) {

        response(
            false,
            "Price must be greater than 0",
            array(),
            422
        );
    }

    if ($stock < 0) {

        response(
            false,
            "Stock cannot be negative",
            array(),
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
            array(
                "error" => $con->error
            ),
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
            array(
                "error" => $error
            ),
            500
        );
    }


    $newProductId =
        (int) $stmt->insert_id;


    $stmt->close();


    response(
        true,
        "Product added successfully",
        array(
            "product_id" => $newProductId,
            "image" =>
                $image !== ""
                    ? $image
                    : null
        ),
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

    $productId =
        isset($data["product_id"])
            ? (int) $data["product_id"]
            : 0;


    if ($productId <= 0) {

        response(
            false,
            "product_id is required",
            array(),
            422
        );
    }


    $fields = array();
    $types = "";
    $values = array();


    /*
    |--------------------------------------------------------------------------
    | NAME
    |--------------------------------------------------------------------------
    */

    if (
        array_key_exists(
            "name",
            $data
        )
    ) {

        $name =
            trim(
                (string) $data["name"]
            );

        if ($name === "") {

            response(
                false,
                "Product name cannot be empty",
                array(),
                422
            );
        }

        $fields[] = "name = ?";
        $types .= "s";
        $values[] = $name;
    }


    /*
    |--------------------------------------------------------------------------
    | CATEGORY
    |--------------------------------------------------------------------------
    */

    if (
        array_key_exists(
            "category",
            $data
        )
    ) {

        $category =
            trim(
                (string) $data["category"]
            );

        if ($category === "") {

            response(
                false,
                "Product category cannot be empty",
                array(),
                422
            );
        }

        $fields[] = "category = ?";
        $types .= "s";
        $values[] = $category;
    }


    /*
    |--------------------------------------------------------------------------
    | PRICE
    |--------------------------------------------------------------------------
    */

    if (
        array_key_exists(
            "price",
            $data
        )
    ) {

        $price =
            (float) $data["price"];

        if ($price <= 0) {

            response(
                false,
                "Price must be greater than 0",
                array(),
                422
            );
        }

        $fields[] = "price = ?";
        $types .= "d";
        $values[] = $price;
    }


    /*
    |--------------------------------------------------------------------------
    | STOCK
    |--------------------------------------------------------------------------
    */

    if (
        array_key_exists(
            "stock",
            $data
        )
    ) {

        $stock =
            (int) $data["stock"];

        if ($stock < 0) {

            response(
                false,
                "Stock cannot be negative",
                array(),
                422
            );
        }

        $fields[] = "stock = ?";
        $types .= "i";
        $values[] = $stock;
    }


    /*
    |--------------------------------------------------------------------------
    | IMAGE
    |--------------------------------------------------------------------------
    */

    if (
        array_key_exists(
            "image",
            $data
        )
    ) {

        $image =
            trim(
                (string) $data["image"]
            );

        $fields[] = "image = ?";
        $types .= "s";
        $values[] = $image;
    }


    /*
    |--------------------------------------------------------------------------
    | STATUS
    |--------------------------------------------------------------------------
    */

    if (
        array_key_exists(
            "status",
            $data
        )
    ) {

        $status =
            trim(
                (string) $data["status"]
            );

        if ($status === "") {

            response(
                false,
                "Product status cannot be empty",
                array(),
                422
            );
        }

        $fields[] = "status = ?";
        $types .= "s";
        $values[] = $status;
    }


    /*
    |--------------------------------------------------------------------------
    | NOTHING TO UPDATE
    |--------------------------------------------------------------------------
    */

    if (empty($fields)) {

        response(
            false,
            "No fields to update",
            array(),
            422
        );
    }


    /*
    |--------------------------------------------------------------------------
    | BUILD QUERY
    |--------------------------------------------------------------------------
    */

    $sql =
        "UPDATE products SET " .
        implode(", ", $fields) .
        " WHERE product_id = ?";


    $types .= "i";
    $values[] = $productId;


    $stmt = $con->prepare($sql);


    if (!$stmt) {

        response(
            false,
            "Failed to prepare product update",
            array(
                "error" => $con->error
            ),
            500
        );
    }


    /*
    |--------------------------------------------------------------------------
    | DYNAMIC BIND
    |--------------------------------------------------------------------------
    */

    $bindParams = array();
    $bindParams[] = $types;

    foreach ($values as $key => $value) {

        $bindParams[] = &$values[$key];
    }


    if (
        !call_user_func_array(
            array(
                $stmt,
                "bind_param"
            ),
            $bindParams
        )
    ) {

        $stmt->close();

        response(
            false,
            "Failed to bind update parameters",
            array(),
            500
        );
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
            "Failed to update product",
            array(
                "error" => $error
            ),
            500
        );
    }


    $affectedRows =
        $stmt->affected_rows;


    $stmt->close();


    if ($affectedRows === 0) {

        response(
            true,
            "Product updated successfully",
            array(
                "product_id" => $productId,
                "changed" => false
            ),
            200
        );
    }


    response(
        true,
        "Product updated successfully",
        array(
            "product_id" => $productId,
            "changed" => true
        ),
        200
    );
}


/*
|--------------------------------------------------------------------------
| DELETE PRODUCT
|--------------------------------------------------------------------------
*/

if ($method === "DELETE") {

    $productId =
        isset($data["product_id"])
            ? (int) $data["product_id"]
            : (
                isset($_GET["product_id"])
                    ? (int) $_GET["product_id"]
                    : 0
            );


    if ($productId <= 0) {

        response(
            false,
            "product_id is required",
            array(),
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
            array(
                "error" => $con->error
            ),
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
            array(
                "error" => $error
            ),
            500
        );
    }


    if ($stmt->affected_rows === 0) {

        $stmt->close();

        response(
            false,
            "Product not found",
            array(),
            404
        );
    }


    $stmt->close();


    response(
        true,
        "Product deleted successfully",
        array(
            "product_id" => $productId
        ),
        200
    );
}


/*
|--------------------------------------------------------------------------
| UNSUPPORTED REQUEST
|--------------------------------------------------------------------------
*/

response(
    false,
    "Unsupported request method",
    array(),
    405
);

?>