<?php

namespace kozlovsv\jwtauth;

/**
 * Interface to work with token storage
 * @package kozlovsv\jwtauth
 * @author Kozlov Sergey <kozlovsv78@gmail.com>
 */
interface ITokenStorageInterface
{
    /**
     * Check exists token in storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token exists
     */
    public function exists(int $userId, string $tokenId): bool;

    /**
     * Save token to storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token saved
     */
    public function set(int $userId, string $tokenId): bool;

    /**
     * Delete token from storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token deleted
     */
    public function delete(int $userId, string $tokenId): bool;
}