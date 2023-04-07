<?php

namespace kozlovsv\jwtauth;

use Yii;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\di\Instance;

/**
 * Service provides token storage in application cache
 */
class TokenStorageCache extends Component implements ITokenStorageIntegface
{
    const ACCESS_TOKEN_TYPE = 'a';
    const REFRESH_TOKEN_TYPE = 'a';

    /**
     * Main Prefix for chache keys
     * @var string
     */
    public $cacheKeyPrefix = 'api:token:';

    /**
     * Duration Access Token in second
     * Default: 30 min
     * @var string
     */
    public $durationAccess = 1800;

    /**
     * Duration Refresh Token in second
     * Default: 15 days
     * @var string
     */
    public $durationRefresh = 1296000;

    /**
     * When checking nbf, iat or expiration times,
     * we want to provide some extra leeway time to
     * account for clock skew.
     *
     * @var int
     */
    public $leeway = 0;

    /**
     * @var yii\caching\CacheInterface|string|array
     */
    protected $cache = 'cache';

    /**
     * @inheritDoc
     *
     * @throws InvalidConfigException
     */
    public function init()
    {
        parent::init();
        $this->cache = Instance::ensure($this->cache);
        if (!$this->cache) {
            throw new InvalidConfigException('The Cache component is required.');
        }
    }

    /**
     * Build cache key for user
     * @param int $userId
     * @param string $tokenType Type token. For Example a - for Access token, r - for refresh tocken
     * @return string
     */
    protected function buildKeyForUser(int $userId, string $tokenType = self::ACCESS_TOKEN_TYPE): string
    {
        return "$this->cacheKeyPrefix$userId:$tokenType";
    }

    /**
     * Build formated cache key, for example:  api:token:1425:a:9f3898ca702c9c9f4991c63dc7eb0e13
     * 1425 - User ID
     * f3898ca702c9c9f4991c63dc7eb0e13 - Tocken Id
     *
     * This key structure allows you to get all the tokens for a specific user by running a Redis query
     * KEYS api:token:1425:* - all tokens for user
     * KEYS api:token:1425:a:* - all access tokens for user
     * KEYS api:token:1425:r:* - all refresh tokens for user
     *
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @param string $tokenType Type token. For Example a - for Access token, r - for refresh tocken
     * @return string Formated cache key
     */
    protected function buildKey(int $userId, string $tokenId, string $tokenType = self::ACCESS_TOKEN_TYPE): string
    {
        return $this->buildKeyForUser($userId, $tokenType) . ':' . $tokenId;
    }

    /**
     * Check exists token in storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @param string $tokenType Type token. For Example a - for Access token, r - for refresh tocken
     * @return bool True if token exists
     */
    public function exists(int $userId, string $tokenId, string $tokenType = self::ACCESS_TOKEN_TYPE): bool
    {
        $key = $this->buildKey($userId, $tokenId, $tokenType);
        return $this->cache->exists($key);
    }

    /**
     * Save token to storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @param string $tokenType Type token. For Example a - for Access token, r - for refresh tocken
     * @param int $duration the number of seconds in which the cached value will expire. 0 means never expire.
     * @return bool True if token exists
     */
    protected function set(int $userId, string $tokenId, string $tokenType, int $duration): bool
    {
        $key = $this->buildKey($userId, $tokenId, $tokenType);
        return $this->cache->set($key, 1, $duration + $this->leeway);
    }

    /**
     * Delete token from storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @param string $tokenType Type token. For Example a - for Access token, r - for refresh tocken
     * @return bool True if token deleted
     */
    protected function delete(int $userId, string $tokenId, string $tokenType): bool
    {
        $key = $this->buildKey($userId, $tokenId, $tokenType);
        return $this->cache->delete($key);
    }

    /**
     * Delete access token from storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token deleted
     */
    public function deleteAccessToken(int $userId, string $tokenId): bool
    {
        return $this->delete($userId, $tokenId, self::ACCESS_TOKEN_TYPE);
    }

    /**
     * Delete refresh token from storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token deleted
     */
    public function deletetRefreshToken(int $userId, string $tokenId): bool
    {
        return $this->delete($userId, $tokenId, self::REFRESH_TOKEN_TYPE);
    }

    /**
     * Save Access token to storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token saved
     */
    public function setAccessToken(int $userId, string $tokenId): bool
    {
        return $this->set($userId, $tokenId, self::ACCESS_TOKEN_TYPE, $this->durationAccess);
    }

    /**
     * Save Refresh token to storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token saved
     */
    public function setRefreshToken(int $userId, string $tokenId): bool
    {
        return $this->set($userId, $tokenId, self::REFRESH_TOKEN_TYPE, $this->durationRefresh);
    }

    /**
     * Check exists Refresh token in storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token exists
     */
    public function existsAccessToken(int $userId, string $tokenId): bool
    {
        return $this->exists($userId, $tokenId);
    }

    /**
     * Save Access token to storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token saved
     */
    public function existsRefreshToken(int $userId, string $tokenId): bool
    {
        return $this->exists($userId, $tokenId, self::REFRESH_TOKEN_TYPE);
    }
}
