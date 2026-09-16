<?php

header("Content-Type: application/json");

require_once "../connection.php";
require_once "../config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function response(bool $status, string $message, array $data = [], int $code = 200): never
{
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
    $headers = function_exists("getallheaders") ? getallheaders() : [];

    $authorization = $headers["Authorization"]
        ?? $headers["authorization"]
        ?? ($_SERVER["HTTP_AUTHORIZATION"] ?? null);

    if (!$authorization || !preg_match("/Bearer\s+(.+)/i", $authorization, $matches)) {
        return null;
    }

    return trim($matches[1]);
}

function authenticate(array $allowedRoles): array
{
    global $secret_key;

    $token = getBearerToken();

    if (!$token) {
        response(false, "Authorization token is required", [], 401);
    }

    try {
        $decoded = JWT::decode($token, new Key($secret_key, "HS256"));
        $payload = (array)$decoded;

        if (($payload["type"] ?? "") !== "access") {
            response(false, "Invalid access token", [], 401);
        }

        $role = $payload["role"] ?? "";

        if (!in_array($role, $allowedRoles, true)) {
            response(false, "You do not have permission for this action", [], 403);
        }

        return $payload;
    } catch (Throwable $e) {
        response(false, "Invalid or expired token", [], 401);
    }
}

function inputData(): array
{
    $raw = file_get_contents("php://input");
    $data = json_decode($raw, true);

    return is_array($data) ? $data : $_POST;
}

$method = $_SERVER["REQUEST_METHOD"];

if ($method === "GET") {
    authenticate(["user", "owner", "admin"]);

    $productId = (int)($_GET["product_id"] ?? 0);

    if ($productId > 0) {
        $stmt = $con->prepare(
            "SELECT product_id, name, category, price, stock, image, status
             FROM products
             WHERE product_id = ?
             LIMIT 1"
        );

        if (!$stmt) {
            response(false, "Database query failed", [], 500);
        }

        $stmt->bind_param("i", $productId);
    } else {
        $stmt = $con->prepare(
            "SELECT product_id, name, category, price, stock, image, status
             FROM products
             WHERE status != 'deleted'
             ORDER BY product_id DESC"
        );

        if (!$stmt) {
            response(false, "Database query failed", [], 500);
        }
    }

    $stmt->execute();
    $result = $stmt->get_result();

    $products = [];

    while ($row = $result->fetch_assoc()) {
        $row["product_id"] = (int)$row["product_id"];
        $row["price"] = (float)$row["price"];
        $row["stock"] = (int)$row["stock"];
        $products[] = $row;
    }

    $stmt->close();

    response(true, "Products fetched successfully", [
        "products" => $products
    ]);
}

$user = authenticate(["admin"]);
$data = inputData();

if ($method === "POST") {
    $name = trim($data["name"] ?? "");
    $category = trim($data["category"] ?? "");
    $price = (float)($data["price"] ?? 0);
    $stock = (int)($data["stock"] ?? 0);
    $image = trim($data["image"] ?? "");
    $status = trim($data["status"] ?? "active");

    if ($name === "" || $category === "" || $price <= 0 || $stock < 0) {
        response(false, "name, category, price and valid stock are required", [], 422);
    }

    $stmt = $con->prepare(
        "INSERT INTO products
        (name, category, price, stock, image, status)
        VALUES (?, ?, ?, ?, ?, ?)"
    );

    if (!$stmt) {
        response(false, "Failed to prepare product insert", [], 500);
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
        response(false, "Failed to add product", [], 500);
    }

    $productId = $stmt->insert_id;
    $stmt->close();

    response(true, "Product added successfully", [
        "product_id" => $productId
    ], 201);
}

if ($method === "PUT" || $method === "PATCH") {
    $productId = (int)($data["product_id"] ?? 0);

    if ($productId <= 0) {
        response(false, "product_id is required", [], 422);
    }

    $fields = [];
    $types = "";
    $values = [];

    if (array_key_exists("name", $data)) {
        $fields[] = "name = ?";
        $types .= "s";
        $values[] = trim($data["name"]);
    }

    if (array_key_exists("category", $data)) {
        $fields[] = "category = ?";
        $types .= "s";
        $values[] = trim($data["category"]);
    }

    if (array_key_exists("price", $data)) {
        $fields[] = "price = ?";
        $types .= "d";
        $values[] = (float)$data["price"];
    }

    if (array_key_exists("stock", $data)) {
        $fields[] = "stock = ?";
        $types .= "i";
        $values[] = (int)$data["stock"];
    }

    if (array_key_exists("image", $data)) {
        $fields[] = "image = ?";
        $types .= "s";
        $values[] = trim($data["image"]);
    }

    if (array_key_exists("status", $data)) {
        $fields[] = "status = ?";
        $types .= "s";
        $values[] = trim($data["status"]);
    }

    if ($fields === []) {
        response(false, "No fields to update", [], 422);
    }

    $sql = "UPDATE products SET " . implode(", ", $fields) . " WHERE product_id = ?";
    $types .= "i";
    $values[] = $productId;

    $stmt = $con->prepare($sql);

    if (!$stmt) {
        response(false, "Failed to prepare product update", [], 500);
    }

    $stmt->bind_param($types, ...$values);

    if (!$stmt->execute()) {
        response(false, "Failed to update product", [], 500);
    }

    $stmt->close();

    response(true, "Product updated successfully");
}

if ($method === "DELETE") {
    $productId = (int)($data["product_id"] ?? $_GET["product_id"] ?? 0);

    if ($productId <= 0) {
        response(false, "product_id is required", [], 422);
    }

    /*
     * Soft delete keeps the product record/history safe.
     */
    $stmt = $con->prepare(
        "UPDATE products
         SET status = 'deleted'
         WHERE product_id = ?"
    );

    if (!$stmt) {
        response(false, "Failed to prepare product delete", [], 500);
    }

    $stmt->bind_param("i", $productId);

    if (!$stmt->execute()) {
        response(false, "Failed to delete product", [], 500);
    }

    if ($stmt->affected_rows === 0) {
        $stmt->close();
        response(false, "Product not found", [], 404);
    }

    $stmt->close();

    response(true, "Product deleted successfully");
}

response(false, "Unsupported request method", [], 405);
?>
