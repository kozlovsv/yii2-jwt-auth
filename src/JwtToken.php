<?php

namespace kozlovsv\jwtauth;

use Firebase\JWT\Key;

/**
 * JWT Token Container
 * Class JwtToken
 * @package kozlovsv\jwtauth
 * @author Kozlov Sergey <kozlovsv78@gmail.com>
 */
class JwtToken
{
    /**
     * Raw token
     * @var string
     */
    private $_jwtToken;

    /**
     * Payload section token
     * @var array
     */
    private $_jwtPayload = [];

    /**
     * Payload section token
     * @var array|null
     */
    private $_jwtHeader = null;

    /**
     * Get decoded jwt payload section token
     *
     * @return array
     */
    public function getJwtPayload(): array
    {
        return $this->_jwtPayload;
    }


    /**
     * Get user id
     *
     * @return int
     */
    public function getUserID(): int
    {
        return $this->_jwtPayload['uid'] ?? 0;
    }

    /**
     * Get token ID
     *
     * @return string
     */
    public function getTokenId(): string
    {
        return $this->_jwtPayload['jti'] ?? '';
    }

    /**
     * Set user id
     * @param int $userId
     * @return JwtToken
     */
    public function setUserID(int $userId): JwtToken
    {
        $this->_jwtPayload['uid'] = $userId;
        return $this;
    }

    /**
     * Set token ID
     * @param string $tokenId
     * @return JwtToken
     */
    public function setTokenId(string $tokenId): JwtToken
    {
        $this->_jwtPayload['jti'] = $tokenId;
        return $this;
    }


    /**
     * Get jwt raw token string
     *
     * @return string|null
     */
    public function getJwtToken(): ?string
    {
        return $this->_jwtToken;
    }

    public function __construct($jwtToken = null)
    {
        $this->_jwtToken = $jwtToken;
    }

    public static function setLeeway(int $leeway): void {
        \Firebase\JWT\JWT::$leeway = $leeway;
    }

    /**
     * Decode token with verify sign and expiration. If tiken is not valid, throws exception.
     * @param string $jwtRawToken
     * @param string $key
     * @param string $alg
     * @return JwtToken
    */
    public static function decode(string $jwtRawToken, string $key, string $alg): JwtToken {
        $instace = new self($jwtRawToken);
        $instace->_jwtPayload = \Firebase\JWT\JWT::decode($jwtRawToken, new Key($key, $alg));
        return $instace;
    }

    /**
     * Add custom claims to Payload Section
     * @param array $claims
     * @return $this
     */
    public function addClaims(array $claims): JwtToken {
        $this->_jwtPayload = array_merge($this->_jwtPayload, $claims);
        return $this;
    }

    /**
     * Add custom data to Header section
     * @param array $header
     * @return $this
     */
    public function addHeader(array $header): JwtToken {
        $this->_jwtHeader = array_merge($this->_jwtHeader, $header);
        return $this;
    }

    /**
     * Add Expired at to Payload section. Unix timestamp
     * @param int $duration
     * @return $this
     */
    public function setExpiredAt(int $duration): JwtToken {
        $this->_jwtPayload['exp'] = time() + $duration;
        return $this;
    }

    /**
     * Add Not Before Use parameter to Payload section.
     * @param int $timestamp Unix timestamp
     * @return $this
     */
    public function setNotBeforeUse(int $timestamp): JwtToken {
        $this->_jwtPayload['nbf'] = $timestamp;
        return $this;
    }

    /**
     * Set random token id to payload
     * @param int $userId
     * @return $this
     */
    public function setRandomTokenId(int $userId): JwtToken {
        $id = self::generateRandomTokenId($userId);
        $this->setTokenId($id);
        return $this;
    }

    /**
     * MD5 Hashed random string
     * @param mixed $salt
     * @return string
     */
    public static function generateRandomTokenId($salt): string {
        return md5(uniqid(rand(), true) . $salt);
    }

    /**
     * Generate JWT token
     * @param string $key
     * @param string $alg
     * @return string
     */
    public function encode(string $key, string $alg){
        $this->_jwtToken = \Firebase\JWT\JWT::encode($this->_jwtPayload, $key, $alg, null, $this->_jwtHeader);
        return $this->_jwtToken;
    }
}