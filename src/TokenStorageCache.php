<?php

namespace kozlovsv\jwtauth;

use Exception;
use Yii;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\di\Instance;

/**
 * Service provides token storage in application cache
 * @package kozlovsv\jwtauth
 * @author Kozlov Sergey <kozlovsv78@gmail.com>
 */
class TokenStorageCache extends Component implements ITokenStorageInterface
{
    /**
     * Main Prefix for chache keys
     * @var string
     */
    public $cacheKeyPrefix = 'api:token:';

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
    }

    /**
     * Build cache key for user
     * @param int $userId
     * @return string
     */
    protected function buildKeyForUser(int $userId): string
    {
        return "$this->cacheKeyPrefix$userId";
    }

    /**
     * Build formated cache key, for example:  api:token:1425:9f3898ca702c9c9f4991c63dc7eb0e13
     * 1425 - User ID
     * f3898ca702c9c9f4991c63dc7eb0e13 - Tocken Id
     *
     * This key structure allows you to get all the tokens for a specific user by running a Redis query
     * KEYS api:token:1425:* - all tokens for user
     *
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return string Formated cache key
     */
    protected function buildKeyForUserToken(int $userId, string $tokenId): string
    {
        return $this->buildKeyForUser($userId) . ':' . $tokenId;
    }

    /**
     * Build formated cache key, for example:  api:token:1425:9f3898ca702c9c9f4991c63dc7eb0e13
     * 1425 - User ID
     * f3898ca702c9c9f4991c63dc7eb0e13 - Tocken Id
     *
     * This key structure allows you to get all the tokens for a specific user by running a Redis query
     * KEYS api:token:1425:* - all tokens for user
     *
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return string Formated cache key
     */
    protected function buildKey(int $userId, string $tokenId): string
    {
        return $this->buildKeyForUserToken($userId, $tokenId);
    }

    /**
     * Check exists key in storage
     * Low-lefel function work with storage
     * @param string $key a key identifying the cached value.
     * @return bool True if token exists
     */
    protected function _exists(string $key): bool{
        return $this->cache->exists($key);
    }

    /**
     * Stores a value identified by a key in storage.
     * @param string $key the key identifying the value to be cached
     * @param mixed $value the value to be stored.
     * @param int $duration the number of seconds in which the cached value will expire. 0 means never expire.
     * @return bool true if the value is successfully stored, false otherwise
     * @throws Exception
     */
    protected function setValue(string $key, $value, int $duration): bool
    {
        return $this->cache->set($key, $value, $duration);
    }

    /**
     * Deletes a value with the specified key from storage
     * @param string $key the key of the value to be deleted
     * @return bool if no error happens during deletion
     */
    protected function deleteValue(string $key): bool {
        return $this->cache->delete($key);
    }

    /**
     * Check exists token in storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @return bool True if token exists
     */
    public function exists(int $userId, string $tokenId): bool
    {
        $key = $this->buildKey($userId, $tokenId);
        return $this->_exists($key);
    }

    /**
     * Save token to storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
     * @param int $duration the number of seconds in which the cached value will expire. 0 means never expire.
     * @return bool True if token exists
     * @throws Exception
     */
    public function set(int $userId, string $tokenId, int $duration = 0): bool
    {
        $key = $this->buildKey($userId, $tokenId);
        $value = YII_DEBUG ? $this->buildKeyForUserToken($userId, $tokenId) : 1;
        return $this->setValue($key, $value, $duration);
    }

    /**
     * Delete token from storage
     * @param int $userId User Id
     * @param string $tokenId Unique token ID, for example hash MD5 or SHA-1, store in jti claim JWT tocken
          * @return bool True if token deleted
     */
    public function delete(int $userId, string $tokenId): bool
    {
        $key = $this->buildKey($userId, $tokenId);
        return $this->deleteValue($key);
    }

    /**
     * Delete all tokens for user from storage
     * @param int $userId User Id
     * @return bool True if token deleted
     */
    public function deleteAllForUser(int $userId): bool
    {
        //Not implemented because the standard Cache component does not have required functionality
        return false;
    }
}