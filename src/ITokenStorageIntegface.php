<?php

namespace kozlovsv\jwtauth;

interface ITokenStorageIntegface
{
    /**
     * Check exists Access token in storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token exists
     */
    public function existsAccessToken(int $userId, string $tokenId): bool;

    /**
     * Check exists Refresh token in storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
      * @return bool True if token exists
     */
    public function existsRefreshToken(int $userId, string $tokenId): bool;

    /**
     * Save Access token to storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token saved
     */
    public function setAccessToken(int $userId, string $tokenId): bool;


    /**
     * Save Refresh token to storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token saved
     */
    public function setRefreshToken(int $userId, string $tokenId): bool;

    /**
     * Delete access token from storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token deleted
     */
    public function deleteAccessToken(int $userId, string $tokenId): bool;


    /**
     * Delete refresh token from storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token deleted
     */
    public function deletetRefreshToken(int $userId, string $tokenId): bool;
}