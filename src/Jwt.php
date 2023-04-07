<?php

namespace kozlovsv\jwtauth;

use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\di\Instance;


/**
 * JSON Web Token Component
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
     * @var ITokenStorageIntegface|string|array the component provide storage token.
     */
    public $tokenStorage;


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

        if (empty($this->tokenStorage)) {
            $this->tokenStorage = [
                'class' => TokenStorageCache::class,
                'durationAccess' => $this->durationAccess,
                'durationRefresh' => $this->durationRefresh,
                'leeway' => $this->leeway,
            ];
        }
        $this->tokenStorage = Instance::ensure($this->tokenStorage);
    }

    /**
     * Parses the JWT and returns a token class
     * @param string $tokenRaw JWT token string
     * @param bool $verifyWhiteList true if need verify token in white list
     * @param bool $isAccess true if Access token, false if Refresh token
     * @return JwtToken|null
     */
    public function parseToken(string $tokenRaw, bool $verifyWhiteList = true, bool $isAccess = true)
    {
        $token = JwtToken::decode($tokenRaw, $this->secretKey, $this->alg);

        if ($verifyWhiteList && !$this->verifyWhiteList($token, $isAccess)) {
            return null;
        }
        return $token;
    }


    /**
     * Validate token
     * @param JwtToken $token token object
     * @param bool $isAccess true if Access token, false if Refresh token
     * @return bool
     */
    public function verifyWhiteList(JwtToken $token, bool $isAccess = true)
    {
        $tokenId = $token->getTokenId();
        $userId = $token->getUserID();
        if (!$tokenId || !$userId) return false;
        return $isAccess ? $this->tokenStorage->existsAccessToken($userId, $tokenId) : $this->tokenStorage->existsRefreshToken($userId, $tokenId);
    }
}
