
<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header(
    'Access-Control-Allow-Headers: Content-Type, Authorization'
);

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once __DIR__ . '/vendor/autoload.php';

// ============================================================
// TOKEN CONFIGURATION
// ============================================================

// Access token: 24 hours
const OWNER_ACCESS_LIFETIME = 24 * 60 * 60;

// Refresh token: 100 days
const OWNER_REFRESH_LIFETIME = 100 * 24 * 60 * 60;

// ============================================================
// RESPONSE
// ============================================================

function ownerResponse(
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
// ENVIRONMENT
// ============================================================

function ownerJwtSecret(): string
{
    $secret = getenv('JWT_SECRET');

    if ($secret === false || trim($secret) === '') {
        ownerResponse(
            false,
            'JWT_SECRET is not configured',
            [],
            500
        );
    }

    return $secret;
}

// ============================================================
// AIVEN DATABASE
// ============================================================

function ownerDb(): mysqli
{
    $host = getenv('DB_HOST');
    $port = (int) (getenv('DB_PORT') ?: 3306);
    $database = getenv('DB_NAME') ?: 'defaultdb';
    $username = getenv('DB_USER');
    $password = getenv('DB_PASSWORD');

    if (
        !$host ||
        $port <= 0 ||
        !$database ||
        !$username ||
        $password === false
    ) {
        ownerResponse(
            false,
            'Database configuration missing',
            [],
            500
        );
    }

    mysqli_report(
        MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT
    );

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
// CREATE OWNER JWT
// ============================================================

function createOwnerToken(
    int $ownerId,
    string $name,
    string $email,
    string $type,
    int $lifetime
): string {
    $now = time();

    return JWT::encode(
        [
            // Preserve the existing owner issuer.
            'iss' => 'sporto-api',

            'sub' => (string) $ownerId,

            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $lifetime,

            'jti' => bin2hex(
                random_bytes(16)
            ),

            // Preserve existing owner claims.
            'user_id' => $ownerId,
            'name' => $name,
            'email' => $email,

            'role' => 'owner',
            'type' => $type
        ],
        ownerJwtSecret(),
        'HS256'
    );
}

// ============================================================
// VERIFY OWNER JWT
// ============================================================

function verifyOwnerToken(
    string $token,
    string $expectedType
): object {
    try {
        $claims = JWT::decode(
            $token,
            new Key(
                ownerJwtSecret(),
                'HS256'
            )
        );
    } catch (Throwable $e) {
        ownerResponse(
            false,
            'Invalid or expired owner token',
            [],
            401
        );
    }

    if (
        ($claims->iss ?? null) !== 'sporto-api' ||
        ($claims->role ?? null) !== 'owner' ||
        ($claims->type ?? null) !== $expectedType
    ) {
        ownerResponse(
            false,
            'Invalid owner token',
            [],
            401
        );
    }

    $ownerId = (int) (
        $claims->user_id ??
        $claims->sub ??
        0
    );

    if ($ownerId <= 0) {
        ownerResponse(
            false,
            'Invalid owner ID',
            [],
            401
        );
    }

    return $claims;
}

// ============================================================
// BEARER TOKEN
// ============================================================

function getOwnerBearerToken(): string
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
        ownerResponse(
            false,
            'Bearer token required',
            [],
            401
        );
    }

    return $matches[1];
}

// ============================================================
// ISSUE OWNER TOKENS
// ============================================================

function issueOwnerTokens(
    mysqli $db,
    int $ownerId,
    string $name,
    string $email
): array {
    $accessToken = createOwnerToken(
        $ownerId,
        $name,
        $email,
        'access',
        OWNER_ACCESS_LIFETIME
    );

    $refreshToken = createOwnerToken(
        $ownerId,
        $name,
        $email,
        'refresh',
        OWNER_REFRESH_LIFETIME
    );

    // Store the refresh token hash, not the raw token.
    $refreshHash = hash(
        'sha256',
        $refreshToken
    );

    $stmt = $db->prepare(
        'UPDATE ownerreg_tb
         SET token = ?,
             refresh_token = ?
         WHERE id = ?'
    );

    $stmt->bind_param(
        'ssi',
        $accessToken,
        $refreshHash,
        $ownerId
    );

    $stmt->execute();

    if ($stmt->affected_rows < 0) {
        throw new RuntimeException(
            'Could not save owner tokens'
        );
    }

    $stmt->close();

    return [
        'access_token' => $accessToken,
        'refresh_token' => $refreshToken,
        'token_type' => 'Bearer',
        'expires_in' => OWNER_ACCESS_LIFETIME,
        'refresh_expires_in' => OWNER_REFRESH_LIFETIME
    ];
}

// ============================================================
// REQUEST VALIDATION
// ============================================================

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST, OPTIONS');

    ownerResponse(
        false,
        'Only POST method is allowed',
        [],
        405
    );
}

$input = file_get_contents(
    'php://input'
);

if (
    $input === false ||
    trim($input) === ''
) {
    ownerResponse(
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
    ownerResponse(
        false,
        'Valid JSON request body is required',
        [],
        400
    );
}

// Accept both JSON action and URL action.
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
        [
            'register',
            'login',
            'refresh',
            'logout'
        ],
        true
    )
) {
    ownerResponse(
        false,
        'Invalid action',
        [],
        400
    );
}

// ============================================================
// OWNER AUTHENTICATION
// ============================================================

try {
    $db = ownerDb();

    switch ($action) {

        // ====================================================
        // OWNER REGISTER
        // ====================================================

        case 'register':

            $name = trim(
                (string) ($data['name'] ?? '')
            );

            $email = strtolower(
                trim(
                    (string) (
                        $data['email'] ?? ''
                    )
                )
            );

            $plainPassword = (string) (
                $data['password'] ?? ''
            );

            if (
                mb_strlen($name) < 2 ||
                mb_strlen($name) > 100
            ) {
                ownerResponse(
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
                ownerResponse(
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
                ownerResponse(
                    false,
                    'Password must contain 8 to 72 characters',
                    [],
                    422
                );
            }

            $check = $db->prepare(
                'SELECT id
                 FROM ownerreg_tb
                 WHERE name = ?
                    OR email = ?
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
                ownerResponse(
                    false,
                    'Name or email is already registered',
                    [],
                    409
                );
            }

            $passwordHash = password_hash(
                $plainPassword,
                PASSWORD_DEFAULT
            );

            $emptyToken = '';
            $emptyRefreshToken = '';
            $emptyProfileImage = '';

            $stmt = $db->prepare(
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

            $ownerId = (int) $db->insert_id;

            $stmt->close();

            ownerResponse(
                true,
                'Owner registered successfully. Please login.',
                [
                    'user_id' => $ownerId,
                    'name' => $name,
                    'email' => $email,
                    'role' => 'owner'
                ],
                201
            );

        // ====================================================
        // OWNER LOGIN
        // ====================================================

        case 'login':

            $ownerLogin = trim(
                (string) (
                    $data['username'] ??
                    $data['name'] ??
                    $data['email'] ??
                    ''
                )
            );

            $loginPassword = (string) (
                $data['password'] ?? ''
            );

            if (
                $ownerLogin === '' ||
                $loginPassword === ''
            ) {
                ownerResponse(
                    false,
                    'Name/email and password are required',
                    [],
                    400
                );
            }

            $stmt = $db->prepare(
                'SELECT
                    id,
                    name,
                    email,
                    password,
                    profile_image_url
                 FROM ownerreg_tb
                 WHERE name = ?
                    OR email = ?
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

            if (
                $owner === null ||
                !password_verify(
                    $loginPassword,
                    (string) $owner['password']
                )
            ) {
                ownerResponse(
                    false,
                    'Invalid name/email or password',
                    [],
                    401
                );
            }

            $ownerId = (int) $owner['id'];
            $name = (string) $owner['name'];
            $email = (string) $owner['email'];

            $tokens = issueOwnerTokens(
                $db,
                $ownerId,
                $name,
                $email
            );

            ownerResponse(
                true,
                'Owner login successful',
                [
                    'user_id' => $ownerId,
                    'name' => $name,
                    'email' => $email,
                    'role' => 'owner',

                    'profile_image_url' =>
                        $owner['profile_image_url'] ??
                        null,

                    ...$tokens
                ]
            );

        // ====================================================
        // OWNER REFRESH
        // ====================================================

        case 'refresh':

            $refreshToken = trim(
                (string) (
                    $data['refresh_token'] ?? ''
                )
            );

            if ($refreshToken === '') {
                ownerResponse(
                    false,
                    'Refresh token required',
                    [],
                    422
                );
            }

            $claims = verifyOwnerToken(
                $refreshToken,
                'refresh'
            );

            $ownerId = (int) (
                $claims->user_id ??
                $claims->sub
            );

            $refreshHash = hash(
                'sha256',
                $refreshToken
            );

            $db->begin_transaction();

            $stmt = $db->prepare(
                'SELECT
                    id,
                    name,
                    email,
                    refresh_token
                 FROM ownerreg_tb
                 WHERE id = ?
                 FOR UPDATE'
            );

            $stmt->bind_param(
                'i',
                $ownerId
            );

            $stmt->execute();

            $owner = $stmt
                ->get_result()
                ->fetch_assoc();

            $stmt->close();

            if (
                !$owner ||
                !hash_equals(
                    (string) $owner['refresh_token'],
                    $refreshHash
                )
            ) {
                $db->rollback();

                ownerResponse(
                    false,
                    'Refresh token revoked or expired',
                    [],
                    401
                );
            }

            // Rotate both tokens.
            // This replaces the old refresh-token hash.

            $tokens = issueOwnerTokens(
                $db,
                $ownerId,
                (string) $owner['name'],
                (string) $owner['email']
            );

            $db->commit();

            ownerResponse(
                true,
                'Owner token refreshed',
                [
                    'user_id' => $ownerId,
                    'role' => 'owner',
                    ...$tokens
                ]
            );

        // ====================================================
        // OWNER LOGOUT
        // ====================================================

        case 'logout':

            $refreshToken = trim(
                (string) (
                    $data['refresh_token'] ?? ''
                )
            );

            if ($refreshToken === '') {
                ownerResponse(
                    false,
                    'Refresh token required',
                    [],
                    422
                );
            }

            $claims = verifyOwnerToken(
                $refreshToken,
                'refresh'
            );

            $ownerId = (int) (
                $claims->user_id ??
                $claims->sub
            );

            $refreshHash = hash(
                'sha256',
                $refreshToken
            );

            $db->begin_transaction();

            $stmt = $db->prepare(
                'SELECT refresh_token
                 FROM ownerreg_tb
                 WHERE id = ?
                 FOR UPDATE'
            );

            $stmt->bind_param(
                'i',
                $ownerId
            );

            $stmt->execute();

            $storedOwner = $stmt
                ->get_result()
                ->fetch_assoc();

            $stmt->close();

            if (
                !$storedOwner ||
                !hash_equals(
                    (string) $storedOwner['refresh_token'],
                    $refreshHash
                )
            ) {
                $db->rollback();

                ownerResponse(
                    false,
                    'Invalid or revoked refresh token',
                    [],
                    401
                );
            }

            // Revoke the stored access and refresh tokens.

            $emptyToken = '';
            $emptyRefresh = '';

            $stmt = $db->prepare(
                'UPDATE ownerreg_tb
                 SET token = ?,
                     refresh_token = ?
                 WHERE id = ?'
            );

            $stmt->bind_param(
                'ssi',
                $emptyToken,
                $emptyRefresh,
                $ownerId
            );

            $stmt->execute();
            $stmt->close();

            $db->commit();

            ownerResponse(
                true,
                'Owner logged out successfully'
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
        'Sporto Owner Auth DB Error: ' .
        $e->getMessage()
    );

    if (
        (int) $e->getCode() === 1062 &&
        $action === 'register'
    ) {
        ownerResponse(
            false,
            'Name or email is already registered',
            [],
            409
        );
    }

    ownerResponse(
        false,
        'Owner database request failed',
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
        'Sporto Owner Auth Error: ' .
        $e->getMessage()
    );

    ownerResponse(
        false,
        'Owner authentication request failed',
        [],
        500
    );
}