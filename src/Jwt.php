<?php

namespace kozlovsv\jwtauth;

use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\di\Instance;

/**
 * JSON Web Token Component
 * @package kozlovsv\jwtauth
 * @author Kozlov Sergey <kozlovsv78@gmail.com>
 */
class Jwt extends Component
{
    /**
     * @var string secret key for sign
     */
    public $secretKey;

    /**
     * @var string secret key for sign
     */
    public $alg = 'HS256';

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
     * @var ITokenStorageInterface|string|array the component provide storage token.
     */
    public $tokenStorage = TokenStorageCache::class;

    /**
     * Additional info to payload section JWT
     * Example :
     *  [
     *      'iss' => 'https://api.example.com',
     *      'aud' => 'https://frontend.example.com',
     *      'sub' => 'subject',
     *  ]
     * @var array
     */
    public $additionalClaims = [];


    /**
     * @inheritDoc
     *
     * @throws InvalidConfigException
     */
    public function init()
    {
        parent::init();
        if (!$this->secretKey) {
            throw new InvalidConfigException('The "secretKey" property сan not be empty.');
        }
        $this->tokenStorage = Instance::ensure($this->tokenStorage);
        JwtToken::setLeeway($this->leeway);
    }

    /**
     * Parses the JWT and returns a token class
     * @param string $tokenRaw JWT token string
     * @param bool $verifyWhiteList true if need verify token in white list
     * @return JwtToken|null
     */
    public function parseToken(string $tokenRaw, bool $verifyWhiteList = true)
    {
        $token = JwtToken::decode($tokenRaw, $this->secretKey, $this->alg);

        if ($verifyWhiteList && !$this->verifyWhiteList($token)) {
            return null;
        }
        return $token;
    }

    /**
     * @param bool $isAccess
     * @param bool $addLeeway
     * @return int
     */
    protected function getDuration(bool $isAccess, bool $addLeeway = false): int
    {
        $duration = $isAccess ? $this->durationAccess : $this->durationRefresh;
        if ($addLeeway) $duration += $this->leeway;
        return $duration;
    }

    /**
     * Generate JWT token
     * @param int $userId
     * @param bool $isAccess true if Access token, false if Refresh token
     * @return array  Return pair token and token id [(string) $tokenString, (string) $tokenId]
     */
    public function generateToken(int $userId, bool $isAccess = true): array
    {
        $duration = $this->getDuration($isAccess);
        $token = new JwtToken();
        $token
            ->addClaims($this->additionalClaims)
            ->setUserID($userId)
            ->setExpiredAt($duration)
            ->setRandomTokenId($userId);
        $tokenRaw = $token->encode($this->secretKey, $this->alg);
        $tokenId = $token->getTokenId();
        return [$tokenRaw, $tokenId];
    }

    /**
     * Generate JWT token and save to storage
     * @param int $userId
     * @param bool $isAccess true if Access token, false if Refresh token
     * @return string
     */
    public function generateAndSaveToken(int $userId, bool $isAccess = true): string
    {
        list($tokenString, $tokenId) = $this->generateToken($userId, $isAccess);
        if ($tokenString) {
            $duration = $this->getDuration($isAccess, true);
            $this->tokenStorage->set($userId, $tokenId, $duration);
        }
        return $tokenString;
    }


    /**
     * Validate token
     * @param JwtToken $token token object
     * @return bool
     */
    public function verifyWhiteList(JwtToken $token)
    {
        $tokenId = $token->getTokenId();
        $userId = $token->getUserID();
        if (!$tokenId || !$userId) return false;
        return $this->tokenStorage->exists($userId, $tokenId);
    }

    /**
     * Renew tokens. Delete old refresh token from storage, and generate new pair refresh and access tokens
     * @param JwtToken $refreshToken token object
     * @return array token pair [(string) $refreshToken, (string) $accessToken]
     */
    public function renewTokens(JwtToken $refreshToken): array
    {
        $userId = $refreshToken->getUserID();
        //Delete old refresh token
        $this->tokenStorage->delete(
            $userId,
            $refreshToken->getTokenId());
        return $this->generateAndSavePairTokens($userId);

    }

    /**
     * Generate new pair refresh and access tokens for user id, and save to storage
     * @param int $userId
     * @return array token pair [(string) $refreshToken, (string) $accessToken]
     */
    public function generateAndSavePairTokens(int $userId): array
    {
        return [$this->generateAndSaveToken($userId, false), $this->generateAndSaveToken($userId)];
    }
}