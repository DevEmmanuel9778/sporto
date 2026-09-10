<?php

$con = new mysqli("127.0.0.1", "root", "", "spoerto_db");

if ($con->connect_error) {
    die("Database connection failed: " . $con->connect_error);
}

?>  