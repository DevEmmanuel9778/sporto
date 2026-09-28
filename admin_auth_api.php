
<?php


use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// ============================================================
// ERROR HANDLING
// ============================================================

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

mysqli_report(
    MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT
);

// ============================================================
// HEADERS / CORS
// ============================================================

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header(
    'Access-Control-Allow-Headers: Content-Type, Authorization'
);
header('Access-Control-Max-Age: 86400');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once __DIR__ . '/vendor/autoload.php';

// ============================================================
// TOKEN CONFIGURATION
// ============================================================

const ADMIN_ACCESS_LIFETIME = 24 * 60 * 60;
const ADMIN_REFRESH_LIFETIME = 100 * 24 * 60 * 60;

// ============================================================
// RESPONSE
// ============================================================

function adminResponse(
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
                'message' => $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES |
        JSON_INVALID_UTF8_SUBSTITUTE
    );

    exit;
}

// ============================================================
// ENVIRONMENT VARIABLES
// ============================================================

function adminEnv(string $name): string
{
    $value = getenv($name);

    if (
        $value === false ||
        trim($value) === ''
    ) {
        error_log(
            'Missing admin environment variable: ' .
            $name
        );

        adminResponse(
            false,
            'Server configuration missing',
            [],
            500
        );
    }

    return $value;
}

function adminSecret(): string
{
    return adminEnv('JWT_SECRET');
}

// ============================================================
// AIVEN DATABASE
// ============================================================

function adminDb(): mysqli
{
    $host = adminEnv('DB_HOST');
    $username = adminEnv('DB_USER');
    $password = getenv('DB_PASSWORD');
    $database = adminEnv('DB_NAME');
    $port = (int) (getenv('DB_PORT') ?: 3306);

    if (
        $password === false ||
        $port <= 0
    ) {
        adminResponse(
            false,
            'Database configuration missing',
            [],
            500
        );
    }

    $db = mysqli_init();

    if ($db === false) {
        throw new RuntimeException(
            'Database initialization failed'
        );
    }

    $ca = getenv('DB_SSL_CA');

    if ($ca) {
        $db->ssl_set(
            null,
            null,
            $ca,
            null,
            null
        );
    }

    $db->real_connect(
        $host,
        $username,
        $password,
        $database,
        $port,
        null,
        MYSQLI_CLIENT_SSL
    );

    $db->set_charset('utf8mb4');

    $db->query(
        "SET time_zone = '+00:00'"
    );

    return $db;
}

// ============================================================
// CREATE ADMIN JWT
// ============================================================

function createAdminToken(
    int $adminId,
    string $username,
    string $type,
    int $lifetime
): string {
    $now = time();

    return JWT::encode(
        [
            'iss' => 'sporto-api',
            'sub' => (string) $adminId,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $lifetime,
            'jti' => bin2hex(
                random_bytes(16)
            ),

            // Existing admin claims.
            'user_id' => $adminId,
            'name' => $username,
            'email' => $username,
            'role' => 'admin',
            'type' => $type
        ],
        adminSecret(),
        'HS256'
    );
}

// ============================================================
// VERIFY ADMIN JWT
// ============================================================

function verifyAdminToken(
    string $token,
    string $expectedType
): object {
    try {
        $claims = JWT::decode(
            $token,
            new Key(
                adminSecret(),
                'HS256'
            )
        );
    } catch (Throwable $e) {
        adminResponse(
            false,
            'Invalid or expired admin token',
            [],
            401
        );
    }

    if (
        ($claims->iss ?? null) !== 'sporto-api' ||
        ($claims->role ?? null) !== 'admin' ||
        ($claims->type ?? null) !== $expectedType
    ) {
        adminResponse(
            false,
            'Invalid admin token',
            [],
            401
        );
    }

    $adminId = (int) (
        $claims->user_id ??
        $claims->sub ??
        0
    );

    if ($adminId <= 0) {
        adminResponse(
            false,
            'Invalid admin ID',
            [],
            401
        );
    }

    return $claims;
}

// ============================================================
// BEARER TOKEN
// ============================================================

function getAdminBearerToken(): string
{
    $header =
        $_SERVER['HTTP_AUTHORIZATION'] ??
        $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ??
        '';

    if (
        $header === '' &&
        function_exists('getallheaders')
    ) {
        foreach (getallheaders() as $key => $value) {
            if (
                strcasecmp(
                    $key,
                    'Authorization'
                ) === 0
            ) {
                $header = $value;
                break;
            }
        }
    }

    if (
        !preg_match(
            '/^Bearer\s+(\S+)$/i',
            trim($header),
            $matches
        )
    ) {
        adminResponse(
            false,
            'Bearer token required',
            [],
            401
        );
    }

    return $matches[1];
}

// ============================================================
// FIND CONFIGURED ADMIN
// ============================================================

function findAdmin(
    mysqli $db,
    string $username
): ?array {
    $stmt = $db->prepare(
        'SELECT id, username
         FROM adminreg_tb
         WHERE username = ?
         LIMIT 1'
    );

    $stmt->bind_param(
        's',
        $username
    );

    $stmt->execute();

    $admin = $stmt
        ->get_result()
        ->fetch_assoc();

    $stmt->close();

    return $admin ?: null;
}

// ============================================================
// ISSUE ADMIN TOKENS
// ============================================================

function issueAdminTokens(
    mysqli $db,
    int $adminId,
    string $username
): array {
    $accessToken = createAdminToken(
        $adminId,
        $username,
        'access',
        ADMIN_ACCESS_LIFETIME
    );

    $refreshToken = createAdminToken(
        $adminId,
        $username,
        'refresh',
        ADMIN_REFRESH_LIFETIME
    );

    $refreshHash = hash(
        'sha256',
        $refreshToken
    );

    $expiresAt = gmdate(
        'Y-m-d H:i:s',
        time() + ADMIN_REFRESH_LIFETIME
    );

    // Preserve existing access-token column.
    $stmt = $db->prepare(
        'UPDATE adminreg_tb
         SET token = ?
         WHERE id = ?'
    );

    $stmt->bind_param(
        'si',
        $accessToken,
        $adminId
    );

    $stmt->execute();
    $stmt->close();

    // Store only the refresh-token hash.
    $stmt = $db->prepare(
        'INSERT INTO admin_refresh_tokens
         (admin_id, token_hash, expires_at)
         VALUES (?, ?, ?)'
    );

    $stmt->bind_param(
        'iss',
        $adminId,
        $refreshHash,
        $expiresAt
    );

    $stmt->execute();
    $stmt->close();

    return [
        'access_token' => $accessToken,
        'refresh_token' => $refreshToken,
        'token_type' => 'Bearer',
        'expires_in' => ADMIN_ACCESS_LIFETIME,
        'refresh_expires_in' => ADMIN_REFRESH_LIFETIME
    ];
}

// ============================================================
// REQUEST METHOD
// ============================================================

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST, OPTIONS');

    adminResponse(
        false,
        'Only POST requests are allowed',
        [],
        405
    );
}

// ============================================================
// JSON BODY
// ============================================================

$rawInput = file_get_contents(
    'php://input'
);

if (
    $rawInput === false ||
    trim($rawInput) === ''
) {
    adminResponse(
        false,
        'Request body is required',
        [],
        400
    );
}

$data = json_decode(
    $rawInput,
    true
);

if (!is_array($data)) {
    adminResponse(
        false,
        'Invalid JSON request',
        [],
        400
    );
}

// Support JSON action and URL action.
$action = strtolower(
    trim(
        (string) (
            $data['action'] ??
            $_GET['action'] ??
            ''
        )
    )
);

if (
    !in_array(
        $action,
        ['login', 'refresh', 'logout'],
        true
    )
) {
    adminResponse(
        false,
        'Invalid action',
        [],
        400
    );
}

// ============================================================
// ADMIN AUTHENTICATION
// ============================================================

try {
    $configuredUsername = adminEnv(
        'ADMIN_USERNAME'
    );

    $configuredPasswordHash = adminEnv(
        'ADMIN_PASSWORD_HASH'
    );

    $db = adminDb();

    switch ($action) {

        // ====================================================
        // ADMIN LOGIN
        // ====================================================

        case 'login':

            $loginUsername = trim(
                (string) (
                    $data['username'] ??
                    $data['email'] ??
                    ''
                )
            );

            $loginPassword = (string) (
                $data['password'] ?? ''
            );

            if (
                $loginUsername === '' ||
                $loginPassword === ''
            ) {
                adminResponse(
                    false,
                    'Username and password are required',
                    [],
                    400
                );
            }

            $usernameValid = hash_equals(
                $configuredUsername,
                $loginUsername
            );

            $passwordValid = password_verify(
                $loginPassword,
                $configuredPasswordHash
            );

            if (
                !$usernameValid ||
                !$passwordValid
            ) {
                adminResponse(
                    false,
                    'Invalid username or password',
                    [],
                    401
                );
            }

            $admin = findAdmin(
                $db,
                $configuredUsername
            );

            if (!$admin) {
                adminResponse(
                    false,
                    'Admin account is not configured',
                    [],
                    500
                );
            }

            $adminId = (int) $admin['id'];

            $db->begin_transaction();

            $tokens = issueAdminTokens(
                $db,
                $adminId,
                $configuredUsername
            );

            $db->commit();

            adminResponse(
                true,
                'Admin login successful',
                [
                    'user_id' => $adminId,
                    'name' => $configuredUsername,
                    'email' => $configuredUsername,
                    'role' => 'admin',
                    ...$tokens
                ]
            );

        // ====================================================
        // ADMIN REFRESH
        // ====================================================

        case 'refresh':

            $refreshToken = trim(
                (string) (
                    $data['refresh_token'] ?? ''
                )
            );

            if ($refreshToken === '') {
                adminResponse(
                    false,
                    'Refresh token required',
                    [],
                    422
                );
            }

            $claims = verifyAdminToken(
                $refreshToken,
                'refresh'
            );

            $adminId = (int) (
                $claims->user_id ??
                $claims->sub
            );

            $refreshHash = hash(
                'sha256',
                $refreshToken
            );

            $db->begin_transaction();

            $stmt = $db->prepare(
                'SELECT id
                 FROM admin_refresh_tokens
                 WHERE admin_id = ?
                   AND token_hash = ?
                   AND revoked_at IS NULL
                   AND expires_at > UTC_TIMESTAMP()
                 FOR UPDATE'
            );

            $stmt->bind_param(
                'is',
                $adminId,
                $refreshHash
            );

            $stmt->execute();

            $storedToken = $stmt
                ->get_result()
                ->fetch_assoc();

            $stmt->close();

            if (!$storedToken) {
                $db->rollback();

                adminResponse(
                    false,
                    'Refresh token revoked or expired',
                    [],
                    401
                );
            }

            // Verify that the admin still exists.
            $admin = findAdmin(
                $db,
                $configuredUsername
            );

            if (
                !$admin ||
                (int) $admin['id'] !== $adminId
            ) {
                $db->rollback();

                adminResponse(
                    false,
                    'Admin account not found',
                    [],
                    401
                );
            }

            // Revoke old refresh token.
            $storedId = (int) $storedToken['id'];

            $stmt = $db->prepare(
                'UPDATE admin_refresh_tokens
                 SET revoked_at = UTC_TIMESTAMP()
                 WHERE id = ?'
            );

            $stmt->bind_param(
                'i',
                $storedId
            );

            $stmt->execute();
            $stmt->close();

            // Generate a new token pair.
            $tokens = issueAdminTokens(
                $db,
                $adminId,
                $configuredUsername
            );

            $db->commit();

            adminResponse(
                true,
                'Admin token refreshed',
                [
                    'user_id' => $adminId,
                    'role' => 'admin',
                    ...$tokens
                ]
            );

        // ====================================================
        // ADMIN LOGOUT
        // ====================================================

        case 'logout':

            $refreshToken = trim(
                (string) (
                    $data['refresh_token'] ?? ''
                )
            );

            if ($refreshToken === '') {
                adminResponse(
                    false,
                    'Refresh token required',
                    [],
                    422
                );
            }

            $claims = verifyAdminToken(
                $refreshToken,
                'refresh'
            );

            $adminId = (int) (
                $claims->user_id ??
                $claims->sub
            );

            $refreshHash = hash(
                'sha256',
                $refreshToken
            );

            $db->begin_transaction();

            $stmt = $db->prepare(
                'SELECT id
                 FROM admin_refresh_tokens
                 WHERE admin_id = ?
                   AND token_hash = ?
                   AND revoked_at IS NULL
                 FOR UPDATE'
            );

            $stmt->bind_param(
                'is',
                $adminId,
                $refreshHash
            );

            $stmt->execute();

            $storedToken = $stmt
                ->get_result()
                ->fetch_assoc();

            $stmt->close();

            if (!$storedToken) {
                $db->rollback();

                adminResponse(
                    false,
                    'Invalid or revoked refresh token',
                    [],
                    401
                );
            }

            $storedId = (int) $storedToken['id'];

            $stmt = $db->prepare(
                'UPDATE admin_refresh_tokens
                 SET revoked_at = UTC_TIMESTAMP()
                 WHERE id = ?'
            );

            $stmt->bind_param(
                'i',
                $storedId
            );

            $stmt->execute();
            $stmt->close();

            $db->commit();

            adminResponse(
                true,
                'Admin logged out successfully'
            );
    }

} catch (mysqli_sql_exception $e) {

    if (isset($db)) {
        try {
            $db->rollback();
        } catch (Throwable $ignored) {
        }
    }

    error_log(
        'Sporto Admin DB Error: ' .
        $e->getMessage()
    );

    adminResponse(
        false,
        'Admin database request failed',
        [],
        500
    );

} catch (Throwable $e) {

    if (isset($db)) {
        try {
            $db->rollback();
        } catch (Throwable $ignored) {
        }
    }

    error_log(
        'Sporto Admin Auth Error: ' .
        $e->getMessage()
    );

    adminResponse(
        false,
        'Admin authentication failed',
        [],
        500
    );
}