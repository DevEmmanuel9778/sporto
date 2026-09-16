<?php

require_once "db.php";

$result = $conn->query("SELECT 1 AS test");

if ($result) {
    $row = $result->fetch_assoc();

    echo "Database Read Test: SUCCESS<br>";
    echo "Result: " . $row['test'];
} else {
    echo "Database Read Test: FAILED<br>";
    echo $conn->error;
}
$port = (int) getenv('DB_PORT');
$dbname = getenv('DB_NAME');
$username = getenv('DB_USER');
$password = getenv('DB_PASSWORD');