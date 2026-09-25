<?php

header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

/*
|--------------------------------------------------------------------------
| CORS Preflight
|--------------------------------------------------------------------------
*/
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;

/*
|--------------------------------------------------------------------------
| Response Helper
|--------------------------------------------------------------------------
*/
function sendResponse(
    bool $status,
    string $message,
    array $data = [],
    int $httpCode = 200
): never {
    http_response_code($httpCode);

    echo json_encode(
        array_merge(
            [
                'status' => $status,
                'message' => $message,
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE
    );

    exit;
}

/*
|--------------------------------------------------------------------------
| Request Method
|--------------------------------------------------------------------------
*/
$method = $_SERVER['REQUEST_METHOD'] ?? '';

if ($method !== 'POST') {
    header('Allow: POST, OPTIONS');

    sendResponse(
        false,
        'Only POST method is allowed',
        [],
        405
    );
}

/*
|--------------------------------------------------------------------------
| JSON Request
|--------------------------------------------------------------------------
*/
$input = file_get_contents('php://input');

if ($input === false || trim($input) === '') {
    sendResponse(
        false,
        'Request body is required',
        [],
        400
    );
}

$data = json_decode(
    $input,
    true
);

if (!is_array($data)) {
    sendResponse(
        false,
        'Valid JSON request body is required',
        [],
        400
    );
}

/*
|--------------------------------------------------------------------------
| Action
|--------------------------------------------------------------------------
|
| register
| login
|
*/
$action = strtolower(
    trim((string)($data['action'] ?? ''))
);

if (!in_array($action, ['register', 'login'], true)) {
    sendResponse(
        false,
        'Invalid action. Use register or login',
        [],
        400
    );
}

/*
|--------------------------------------------------------------------------
| Environment Variables
|--------------------------------------------------------------------------
*/
$host = getenv('DB_HOST');
$port = (int)(getenv('DB_PORT') ?: 0);
$dbname = getenv('DB_NAME');
$username = getenv('DB_USER');
$password = getenv('DB_PASSWORD');
$secretKey = getenv('JWT_SECRET');

if (
    $host === false ||
    trim($host) === '' ||
    $port <= 0 ||
    $dbname === false ||
    trim($dbname) === '' ||
    $username === false ||
    trim($username) === '' ||
    $password === false
) {
    sendResponse(
        false,
        'Database environment variables are missing or invalid',
        [],
        500
    );
}

if (
    $secretKey === false ||
    trim($secretKey) === ''
) {
    sendResponse(
        false,
        'JWT_SECRET environment variable is missing',
        [],
        500
    );
}

/*
|--------------------------------------------------------------------------
| Database Connection
|--------------------------------------------------------------------------
*/
try {
    mysqli_report(
        MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT
    );

    $con = mysqli_init();

    if ($con === false) {
        throw new RuntimeException(
            'Could not initialize database connection'
        );
    }

    mysqli_ssl_set(
        $con,
        null,
        null,
        null,
        null,
        null
    );

    mysqli_real_connect(
        $con,
        $host,
        $username,
        $password,
        $dbname,
        $port,
        null,
        MYSQLI_CLIENT_SSL
    );

    $con->set_charset('utf8mb4');
} catch (Throwable $e) {
    error_log(
        'Owner auth DB connection error: ' .
        $e->getMessage()
    );

    sendResponse(
        false,
        'Database connection failed',
        [],
        500
    );
}

/*
|--------------------------------------------------------------------------
| OWNER REGISTER
|--------------------------------------------------------------------------
*/
if ($action === 'register') {
    $name = trim(
        (string)($data['name'] ?? '')
    );

    $email = strtolower(
        trim(
            (string)($data['email'] ?? '')
        )
    );

    $plainPassword = (string)(
        $data['password'] ?? ''
    );

    /*
    |--------------------------------------------------------------------------
    | Validation
    |--------------------------------------------------------------------------
    */
    if (
        mb_strlen($name) < 2 ||
        mb_strlen($name) > 100
    ) {
        sendResponse(
            false,
            'Name must contain 2 to 100 characters',
            [],
            422
        );
    }

    if (
        !filter_var(
            $email,
            FILTER_VALIDATE_EMAIL
        ) ||
        strlen($email) > 254
    ) {
        sendResponse(
            false,
            'A valid email is required',
            [],
            422
        );
    }

    if (
        strlen($plainPassword) < 8 ||
        strlen($plainPassword) > 72
    ) {
        sendResponse(
            false,
            'Password must contain 8 to 72 characters',
            [],
            422
        );
    }

    try {
        /*
        |--------------------------------------------------------------------------
        | Duplicate Check
        |--------------------------------------------------------------------------
        */
        $check = $con->prepare(
            'SELECT id
             FROM ownerreg_tb
             WHERE name = ? OR email = ?
             LIMIT 1'
        );

        $check->bind_param(
            'ss',
            $name,
            $email
        );

        $check->execute();

        $existing = $check
            ->get_result()
            ->fetch_assoc();

        $check->close();

        if ($existing !== null) {
            sendResponse(
                false,
                'Name or email is already registered',
                [],
                409
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Password Hash
        |--------------------------------------------------------------------------
        */
        $passwordHash = password_hash(
            $plainPassword,
            PASSWORD_DEFAULT
        );

        if ($passwordHash === false) {
            throw new RuntimeException(
                'Password hashing failed'
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Insert Owner
        |--------------------------------------------------------------------------
        |
        | These values keep the insert compatible with schemas where
        | token / refresh_token / profile_image_url are NOT NULL.
        |
        */
        $emptyToken = '';
        $emptyRefreshToken = '';
        $emptyProfileImage = '';

        $stmt = $con->prepare(
            'INSERT INTO ownerreg_tb
            (
                name,
                email,
                password,
                token,
                refresh_token,
                profile_image_url
            )
            VALUES (?, ?, ?, ?, ?, ?)'
        );

        $stmt->bind_param(
            'ssssss',
            $name,
            $email,
            $passwordHash,
            $emptyToken,
            $emptyRefreshToken,
            $emptyProfileImage
        );

        $stmt->execute();

        $ownerId = (int)$con->insert_id;

        $stmt->close();

        /*
        |--------------------------------------------------------------------------
        | Registration Success
        |--------------------------------------------------------------------------
        */
        sendResponse(
            true,
            'Owner registered successfully. Please login.',
            [
                'user_id' => $ownerId,
                'name' => $name,
                'email' => $email,
                'role' => 'owner',
            ],
            201
        );
    } catch (mysqli_sql_exception $e) {
        error_log(
            'Owner registration database error: ' .
            $e->getMessage()
        );

        if ((int)$e->getCode() === 1062) {
            sendResponse(
                false,
                'Name or email is already registered',
                [],
                409
            );
        }

        sendResponse(
            false,
            'Registration failed. Please check the owner database table.',
            [],
            500
        );
    } catch (Throwable $e) {
        error_log(
            'Owner registration error: ' .
            $e->getMessage()
        );

        sendResponse(
            false,
            'Registration failed',
            [],
            500
        );
    }
}

/*
|--------------------------------------------------------------------------
| OWNER LOGIN
|--------------------------------------------------------------------------
*/
$ownerLogin = trim(
    (string)(
        $data['username']
        ?? $data['name']
        ?? $data['email']
        ?? ''
    )
);

$loginPassword = (string)(
    $data['password'] ?? ''
);

if (
    $ownerLogin === '' ||
    $loginPassword === ''
) {
    sendResponse(
        false,
        'Name/email and password are required',
        [],
        400
    );
}

try {
    /*
    |--------------------------------------------------------------------------
    | Find Owner
    |--------------------------------------------------------------------------
    */
    $stmt = $con->prepare(
        'SELECT
            id,
            name,
            email,
            password,
            profile_image_url
         FROM ownerreg_tb
         WHERE name = ? OR email = ?
         LIMIT 1'
    );

    $stmt->bind_param(
        'ss',
        $ownerLogin,
        $ownerLogin
    );

    $stmt->execute();

    $owner = $stmt
        ->get_result()
        ->fetch_assoc();

    $stmt->close();

    /*
    |--------------------------------------------------------------------------
    | Verify Password
    |--------------------------------------------------------------------------
    */
    if (
        $owner === null ||
        !password_verify(
            $loginPassword,
            (string)$owner['password']
        )
    ) {
        sendResponse(
            false,
            'Invalid name/email or password',
            [],
            401
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Owner Data
    |--------------------------------------------------------------------------
    */
    $ownerId = (int)$owner['id'];
    $name = (string)$owner['name'];
    $email = (string)$owner['email'];

    /*
    |--------------------------------------------------------------------------
    | JWT
    |--------------------------------------------------------------------------
    */
    $issuedAt = time();

    $accessToken = JWT::encode(
        [
            'iss' => 'sporto-api',
            'iat' => $issuedAt,
            'exp' => $issuedAt + 900,
            'user_id' => $ownerId,
            'name' => $name,
            'email' => $email,
            'role' => 'owner',
            'type' => 'access',
        ],
        $secretKey,
        'HS256'
    );

    /*
    |--------------------------------------------------------------------------
    | Save Access Token
    |--------------------------------------------------------------------------
    */
    $updateStmt = $con->prepare(
        'UPDATE ownerreg_tb
         SET token = ?
         WHERE id = ?'
    );

    $updateStmt->bind_param(
        'si',
        $accessToken,
        $ownerId
    );

    $updateStmt->execute();
    $updateStmt->close();

    /*
    |--------------------------------------------------------------------------
    | Login Success
    |--------------------------------------------------------------------------
    */
    sendResponse(
        true,
        'Owner login successful',
        [
            'user_id' => $ownerId,
            'name' => $name,
            'email' => $email,
            'role' => 'owner',
            'profile_image_url' =>
                $owner['profile_image_url'] ?? null,
            'access_token' => $accessToken,
        ]
    );
} catch (Throwable $e) {
    error_log(
        'Owner login error: ' .
        $e->getMessage()
    );

    sendResponse(
        false,
        'Login failed',
        [],
        500
    );
}