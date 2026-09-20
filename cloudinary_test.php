<?php

header("Content-Type: application/json");

echo json_encode([
    "cloud_name" => getenv("CLOUDINARY_CLOUD_NAME"),
    "api_key" => getenv("CLOUDINARY_API_KEY"),
    "secret_exists" => !empty(getenv("CLOUDINARY_API_SECRET"))
]);