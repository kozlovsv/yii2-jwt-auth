<?php

namespace kozlovsv\jwtauth;

use Firebase\JWT\Key;



/**
 *  JwtToken Container
 */
class JwtToken
{
    /**
     * Raw token
     * @var string
     */
    private $_jwtToken;

    /**
     * Parsed Payload section token
     * @var array
     */
    private $_jwtPayload;

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
     * Get jwt raw token string
     *
     * @return string|null
     */
    public function getJwtToken(): ?string
    {
        return $this->_jwtToken;
    }

    private function __construct($jwtToken)
    {
        $this->_jwtToken = $jwtToken;
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
}