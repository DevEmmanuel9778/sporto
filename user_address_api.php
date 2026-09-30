<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/config/jwt.php';

function response(bool $status, string $message, mixed $data = null, int $code = 200): never
{
    http_response_code($code);

    $output = [
        'status' => $status,
        'message' => $message,
    ];

    if ($data !== null) {
        $output['data'] = $data;
    }

    echo json_encode(
        $output,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    exit;
}

function getBearerToken(): ?string
{
    $header = '';

    if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $header = trim($_SERVER['HTTP_AUTHORIZATION']);
    } elseif (function_exists('getallheaders')) {
        $headers = getallheaders();

        foreach ($headers as $key => $value) {
            if (strtolower($key) === 'authorization') {
                $header = trim((string)$value);
                break;
            }
        }
    }

    if ($header === '') {
        return null;
    }

    if (preg_match('/^Bearer\s+(.+)$/i', $header, $matches)) {
        return trim($matches[1]);
    }

    return null;
}

function getJwtSecret(): string
{
    if (defined('JWT_SECRET')) {
        return (string) JWT_SECRET;
    }

    $secret = getenv('JWT_SECRET');

    if ($secret !== false && trim($secret) !== '') {
        return trim($secret);
    }

    response(
        false,
        'JWT configuration is missing.',
        null,
        500
    );
}

function authenticateUser(): int
{
    $token = getBearerToken();

    if ($token === null || $token === '') {
        response(
            false,
            'Authorization token is required.',
            null,
            401
        );
    }

    try {
        $decoded = JWT::decode(
            $token,
            new Key(getJwtSecret(), 'HS256')
        );

        $payload = (array) $decoded;

        $userId = null;

        /*
         * Sporto JWT payload compatibility:
         * Supports common keys used by the existing auth implementation.
         */
        if (isset($payload['user_id'])) {
            $userId = $payload['user_id'];
        } elseif (isset($payload['id'])) {
            $userId = $payload['id'];
        } elseif (isset($payload['sub'])) {
            $userId = $payload['sub'];
        }

        if ($userId === null || !is_numeric($userId)) {
            response(
                false,
                'Invalid user information in token.',
                null,
                401
            );
        }

        return (int) $userId;

    } catch (Throwable $e) {
        response(
            false,
            'Invalid or expired authorization token.',
            null,
            401
        );
    }
}

function getJsonBody(): array
{
    $raw = file_get_contents('php://input');

    if ($raw === false || trim($raw) === '') {
        response(
            false,
            'Request body is empty.',
            null,
            400
        );
    }

    $data = json_decode($raw, true);

    if (!is_array($data)) {
        response(
            false,
            'Invalid JSON request body.',
            null,
            400
        );
    }

    return $data;
}

function validateAddressData(array $data): array
{
    $name = trim((string)($data['name'] ?? ''));
    $phone = trim((string)($data['phone'] ?? ''));
    $address = trim((string)($data['address'] ?? ''));
    $city = trim((string)($data['city'] ?? ''));
    $district = trim((string)($data['district'] ?? ''));
    $state = trim((string)($data['state'] ?? ''));
    $pincode = trim((string)($data['pincode'] ?? ''));

    if ($name === '') {
        response(false, 'Name is required.', null, 422);
    }

    if ($phone === '') {
        response(false, 'Phone number is required.', null, 422);
    }

    if ($address === '') {
        response(false, 'Address is required.', null, 422);
    }

    if ($city === '') {
        response(false, 'City is required.', null, 422);
    }

    if ($district === '') {
        response(false, 'District is required.', null, 422);
    }

    if ($state === '') {
        response(false, 'State is required.', null, 422);
    }

    if ($pincode === '') {
        response(false, 'Pincode is required.', null, 422);
    }

    if (mb_strlen($name) > 100) {
        response(false, 'Name is too long.', null, 422);
    }

    if (mb_strlen($phone) > 20) {
        response(false, 'Phone number is too long.', null, 422);
    }

    if (mb_strlen($city) > 100) {
        response(false, 'City is too long.', null, 422);
    }

    if (mb_strlen($district) > 100) {
        response(false, 'District is too long.', null, 422);
    }

    if (mb_strlen($state) > 100) {
        response(false, 'State is too long.', null, 422);
    }

    if (mb_strlen($pincode) > 10) {
        response(false, 'Pincode is too long.', null, 422);
    }

    return [
        'name' => $name,
        'phone' => $phone,
        'address' => $address,
        'city' => $city,
        'district' => $district,
        'state' => $state,
        'pincode' => $pincode,
    ];
}

function getAddress(mysqli $con, int $userId, int $addressId): ?array
{
    $stmt = mysqli_prepare(
        $con,
        'SELECT
            address_id,
            user_id,
            name,
            phone,
            address,
            city,
            district,
            state,
            pincode,
            is_default,
            created_at,
            updated_at
         FROM user_address_tb
         WHERE address_id = ? AND user_id = ?
         LIMIT 1'
    );

    mysqli_stmt_bind_param($stmt, 'ii', $addressId, $userId);
    mysqli_stmt_execute($stmt);

    $result = mysqli_stmt_get_result($stmt);
    $row = mysqli_fetch_assoc($result);

    mysqli_stmt_close($stmt);

    if (!$row) {
        return null;
    }

    $row['address_id'] = (int)$row['address_id'];
    $row['user_id'] = (int)$row['user_id'];
    $row['is_default'] = (int)$row['is_default'];

    return $row;
}

function setDefaultAddress(
    mysqli $con,
    int $userId,
    int $addressId
): void {
    mysqli_begin_transaction($con);

    try {
        $check = mysqli_prepare(
            $con,
            'SELECT address_id
             FROM user_address_tb
             WHERE address_id = ? AND user_id = ?
             LIMIT 1'
        );

        mysqli_stmt_bind_param(
            $check,
            'ii',
            $addressId,
            $userId
        );

        mysqli_stmt_execute($check);

        $result = mysqli_stmt_get_result($check);
        $exists = mysqli_fetch_assoc($result);

        mysqli_stmt_close($check);

        if (!$exists) {
            mysqli_rollback($con);

            response(
                false,
                'Address not found.',
                null,
                404
            );
        }

        $reset = mysqli_prepare(
            $con,
            'UPDATE user_address_tb
             SET is_default = 0
             WHERE user_id = ?'
        );

        mysqli_stmt_bind_param(
            $reset,
            'i',
            $userId
        );

        mysqli_stmt_execute($reset);
        mysqli_stmt_close($reset);

        $set = mysqli_prepare(
            $con,
            'UPDATE user_address_tb
             SET is_default = 1
             WHERE address_id = ? AND user_id = ?'
        );

        mysqli_stmt_bind_param(
            $set,
            'ii',
            $addressId,
            $userId
        );

        mysqli_stmt_execute($set);
        mysqli_stmt_close($set);

        mysqli_commit($con);

    } catch (Throwable $e) {
        mysqli_rollback($con);

        response(
            false,
            'Failed to set default address.',
            null,
            500
        );
    }
}

try {

    $userId = authenticateUser();

    $method = strtoupper($_SERVER['REQUEST_METHOD']);

    /*
     * ---------------------------------------------------------
     * GET
     * Get all addresses belonging to logged-in user
     * ---------------------------------------------------------
     */
    if ($method === 'GET') {

        $stmt = mysqli_prepare(
            $con,
            'SELECT
                address_id,
                user_id,
                name,
                phone,
                address,
                city,
                district,
                state,
                pincode,
                is_default,
                created_at,
                updated_at
             FROM user_address_tb
             WHERE user_id = ?
             ORDER BY is_default DESC, updated_at DESC, address_id DESC'
        );

        mysqli_stmt_bind_param($stmt, 'i', $userId);
        mysqli_stmt_execute($stmt);

        $result = mysqli_stmt_get_result($stmt);

        $addresses = [];

        while ($row = mysqli_fetch_assoc($result)) {
            $row['address_id'] = (int)$row['address_id'];
            $row['user_id'] = (int)$row['user_id'];
            $row['is_default'] = (int)$row['is_default'];

            $addresses[] = $row;
        }

        mysqli_stmt_close($stmt);

        response(
            true,
            'Addresses fetched successfully.',
            [
                'addresses' => $addresses,
                'count' => count($addresses),
            ]
        );
    }

    /*
     * ---------------------------------------------------------
     * POST
     * Add new address
     *
     * Also supports:
     * action=set_default
     * ---------------------------------------------------------
     */
    if ($method === 'POST') {

        $data = getJsonBody();

        $action = strtolower(
            trim((string)($data['action'] ?? ''))
        );

        /*
         * Set default address
         */
        if ($action === 'set_default') {

            $addressId = filter_var(
                $data['address_id'] ?? null,
                FILTER_VALIDATE_INT
            );

            if ($addressId === false || $addressId === null || $addressId <= 0) {
                response(
                    false,
                    'Valid address_id is required.',
                    null,
                    422
                );
            }

            setDefaultAddress(
                $con,
                $userId,
                (int)$addressId
            );

            $updated = getAddress(
                $con,
                $userId,
                (int)$addressId
            );

            response(
                true,
                'Default address updated successfully.',
                [
                    'address' => $updated,
                ]
            );
        }

        /*
         * Add new address
         */
        $addressData = validateAddressData($data);

        $isDefault = !empty($data['is_default']);

        /*
         * Check whether this is the user's first address.
         */
        $countStmt = mysqli_prepare(
            $con,
            'SELECT COUNT(*) AS total
             FROM user_address_tb
             WHERE user_id = ?'
        );

        mysqli_stmt_bind_param(
            $countStmt,
            'i',
            $userId
        );

        mysqli_stmt_execute($countStmt);

        $countResult = mysqli_stmt_get_result($countStmt);
        $countRow = mysqli_fetch_assoc($countResult);

        mysqli_stmt_close($countStmt);

        $existingCount = (int)($countRow['total'] ?? 0);

        /*
         * First address automatically becomes default.
         */
        if ($existingCount === 0) {
            $isDefault = true;
        }

        mysqli_begin_transaction($con);

        try {

            /*
             * If this address is default,
             * remove default from existing addresses first.
             */
            if ($isDefault) {

                $reset = mysqli_prepare(
                    $con,
                    'UPDATE user_address_tb
                     SET is_default = 0
                     WHERE user_id = ?'
                );

                mysqli_stmt_bind_param(
                    $reset,
                    'i',
                    $userId
                );

                mysqli_stmt_execute($reset);
                mysqli_stmt_close($reset);
            }

            $stmt = mysqli_prepare(
                $con,
                'INSERT INTO user_address_tb
                (
                    user_id,
                    name,
                    phone,
                    address,
                    city,
                    district,
                    state,
                    pincode,
                    is_default
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
            );

            $defaultValue = $isDefault ? 1 : 0;

            mysqli_stmt_bind_param(
                $stmt,
                'isssssssi',
                $userId,
                $addressData['name'],
                $addressData['phone'],
                $addressData['address'],
                $addressData['city'],
                $addressData['district'],
                $addressData['state'],
                $addressData['pincode'],
                $defaultValue
            );

            mysqli_stmt_execute($stmt);

            $newAddressId = mysqli_insert_id($con);

            mysqli_stmt_close($stmt);

            mysqli_commit($con);

        } catch (Throwable $e) {

            mysqli_rollback($con);

            response(
                false,
                'Failed to create address.',
                null,
                500
            );
        }

        $newAddress = getAddress(
            $con,
            $userId,
            (int)$newAddressId
        );

        response(
            true,
            'Address added successfully.',
            [
                'address' => $newAddress,
            ],
            201
        );
    }

    /*
     * ---------------------------------------------------------
     * PUT / PATCH
     * Update existing address
     * ---------------------------------------------------------
     */
    if ($method === 'PUT' || $method === 'PATCH') {

        $data = getJsonBody();

        $action = strtolower(
            trim((string)($data['action'] ?? ''))
        );

        /*
         * Set default through PATCH
         */
        if ($action === 'set_default') {

            $addressId = filter_var(
                $data['address_id'] ?? null,
                FILTER_VALIDATE_INT
            );

            if ($addressId === false || $addressId === null || $addressId <= 0) {
                response(
                    false,
                    'Valid address_id is required.',
                    null,
                    422
                );
            }

            setDefaultAddress(
                $con,
                $userId,
                (int)$addressId
            );

            $updated = getAddress(
                $con,
                $userId,
                (int)$addressId
            );

            response(
                true,
                'Default address updated successfully.',
                [
                    'address' => $updated,
                ]
            );
        }

        $addressId = filter_var(
            $data['address_id'] ?? null,
            FILTER_VALIDATE_INT
        );

        if ($addressId === false || $addressId === null || $addressId <= 0) {
            response(
                false,
                'Valid address_id is required.',
                null,
                422
            );
        }

        $existing = getAddress(
            $con,
            $userId,
            (int)$addressId
        );

        if ($existing === null) {
            response(
                false,
                'Address not found.',
                null,
                404
            );
        }

        $addressData = validateAddressData($data);

        $requestedDefault = !empty($data['is_default']);

        /*
         * If currently default and the request does not explicitly
         * change it, keep it default.
         */
        $isDefault = array_key_exists('is_default', $data)
            ? ($requestedDefault ? 1 : 0)
            : (int)$existing['is_default'];

        /*
         * Do not allow a user to end up with zero default addresses
         * if they already have multiple addresses.
         */
        if ((int)$existing['is_default'] === 1 && $isDefault === 0) {

            $countStmt = mysqli_prepare(
                $con,
                'SELECT COUNT(*) AS total
                 FROM user_address_tb
                 WHERE user_id = ?'
            );

            mysqli_stmt_bind_param(
                $countStmt,
                'i',
                $userId
            );

            mysqli_stmt_execute($countStmt);

            $countResult = mysqli_stmt_get_result($countStmt);
            $countRow = mysqli_fetch_assoc($countResult);

            mysqli_stmt_close($countStmt);

            $totalAddresses = (int)($countRow['total'] ?? 0);

            if ($totalAddresses > 1) {
                response(
                    false,
                    'Select another default address before removing the current default.',
                    null,
                    422
                );
            }

            $isDefault = 1;
        }

        mysqli_begin_transaction($con);

        try {

            if ($isDefault === 1) {

                $reset = mysqli_prepare(
                    $con,
                    'UPDATE user_address_tb
                     SET is_default = 0
                     WHERE user_id = ?'
                );

                mysqli_stmt_bind_param(
                    $reset,
                    'i',
                    $userId
                );

                mysqli_stmt_execute($reset);
                mysqli_stmt_close($reset);
            }

            $stmt = mysqli_prepare(
                $con,
                'UPDATE user_address_tb
                 SET
                    name = ?,
                    phone = ?,
                    address = ?,
                    city = ?,
                    district = ?,
                    state = ?,
                    pincode = ?,
                    is_default = ?
                 WHERE address_id = ?
                   AND user_id = ?'
            );

            mysqli_stmt_bind_param(
                $stmt,
                'sssssssiii',
                $addressData['name'],
                $addressData['phone'],
                $addressData['address'],
                $addressData['city'],
                $addressData['district'],
                $addressData['state'],
                $addressData['pincode'],
                $isDefault,
                $addressId,
                $userId
            );

            mysqli_stmt_execute($stmt);

            mysqli_stmt_close($stmt);

            mysqli_commit($con);

        } catch (Throwable $e) {

            mysqli_rollback($con);

            response(
                false,
                'Failed to update address.',
                null,
                500
            );
        }

        $updatedAddress = getAddress(
            $con,
            $userId,
            (int)$addressId
        );

        response(
            true,
            'Address updated successfully.',
            [
                'address' => $updatedAddress,
            ]
        );
    }

    /*
     * ---------------------------------------------------------
     * DELETE
     * Delete own address only
     * ---------------------------------------------------------
     */
    if ($method === 'DELETE') {

        $data = [];

        $raw = file_get_contents('php://input');

        if ($raw !== false && trim($raw) !== '') {
            $decoded = json_decode($raw, true);

            if (is_array($decoded)) {
                $data = $decoded;
            }
        }

        $addressId = filter_var(
            $_GET['address_id']
                ?? $data['address_id']
                ?? null,
            FILTER_VALIDATE_INT
        );

        if ($addressId === false || $addressId === null || $addressId <= 0) {
            response(
                false,
                'Valid address_id is required.',
                null,
                422
            );
        }

        $existing = getAddress(
            $con,
            $userId,
            (int)$addressId
        );

        if ($existing === null) {
            response(
                false,
                'Address not found.',
                null,
                404
            );
        }

        /*
         * If deleting the current default address,
         * automatically promote another address.
         */
        $wasDefault = (int)$existing['is_default'] === 1;

        mysqli_begin_transaction($con);

        try {

            $delete = mysqli_prepare(
                $con,
                'DELETE FROM user_address_tb
                 WHERE address_id = ? AND user_id = ?'
            );

            mysqli_stmt_bind_param(
                $delete,
                'ii',
                $addressId,
                $userId
            );

            mysqli_stmt_execute($delete);

            mysqli_stmt_close($delete);

            /*
             * Promote newest remaining address if the deleted
             * address was the default.
             */
            if ($wasDefault) {

                $next = mysqli_prepare(
                    $con,
                    'SELECT address_id
                     FROM user_address_tb
                     WHERE user_id = ?
                     ORDER BY updated_at DESC, address_id DESC
                     LIMIT 1'
                );

                mysqli_stmt_bind_param(
                    $next,
                    'i',
                    $userId
                );

                mysqli_stmt_execute($next);

                $nextResult = mysqli_stmt_get_result($next);
                $nextRow = mysqli_fetch_assoc($nextResult);

                mysqli_stmt_close($next);

                if ($nextRow) {

                    $nextAddressId = (int)$nextRow['address_id'];

                    $promote = mysqli_prepare(
                        $con,
                        'UPDATE user_address_tb
                         SET is_default = 1
                         WHERE address_id = ? AND user_id = ?'
                    );

                    mysqli_stmt_bind_param(
                        $promote,
                        'ii',
                        $nextAddressId,
                        $userId
                    );

                    mysqli_stmt_execute($promote);
                    mysqli_stmt_close($promote);
                }
            }

            mysqli_commit($con);

        } catch (Throwable $e) {

            mysqli_rollback($con);

            response(
                false,
                'Failed to delete address.',
                null,
                500
            );
        }

        response(
            true,
            'Address deleted successfully.'
        );
    }

    response(
        false,
        'Unsupported HTTP method.',
        null,
        405
    );

} catch (mysqli_sql_exception $e) {

    response(
        false,
        'Database error occurred.',
        null,
        500
    );

} catch (Throwable $e) {

    response(
        false,
        'An unexpected server error occurred.',
        null,
        500
    );
}
?>
