<?php

$host = getenv('DB_HOST');
$port = getenv('DB_PORT') ?: 3306;
$dbname = getenv('DB_NAME');
$username = getenv('DB_USER');
$password = getenv('DB_PASSWORD');

$con = new mysqli(
    $host,
    $username,
    $password,
    $dbname,
    (int)$port
);

if ($con->connect_error) {
    die("Database connection failed: " . $con->connect_error);
}

$con->set_charset("utf8mb4");

?>