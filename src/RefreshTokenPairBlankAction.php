<?php

namespace kozlovsv\jwtauth;

use Exception;
use yii\base\Action;
use yii\di\Instance;
use yii\web\UnauthorizedHttpException;

/**
 * Action for refresh token pair Access token and refresh token
 * Abstract class, contains abstract method  getRawToken().
 * @package kozlovsv\jwtauth
 * @author Kozlov Sergey <kozlovsv78@gmail.com>
 */
abstract class RefreshTokenPairBlankAction extends Action
{
    /**
     * @var Jwt|string|array the [[Jwt]] object or the application component ID of the [[Jwt]].
     */
    public $jwt = 'jwt';

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        $this->jwt = Instance::ensure($this->jwt, Jwt::class);
    }

    /**
     * Renew tokens
     *
     * @return array|string[]
     * @throws UnauthorizedHttpException
     */
    public function run()
    {
        $refreshRawToken = $this->getRawToken();
        if (!$refreshRawToken) $this->handleFailure('Refresh token is empty');
        $refreshToken = $this->getJwtAuthToken($refreshRawToken);
        if (!$this->jwt->verifyWhiteList($refreshToken)) {
            $this->handleFailure('Refresh token no longer exists');
        }
        list($newRefreshToken, $newAccessToken) = $this->jwt->renewTokens($refreshToken);
        return $this->formatResponse($newRefreshToken, $newAccessToken);
    }

    /**
     * Create jwt auth token model from
     * @param string $tokenRaw
     * @return JwtToken|null
     * @throws UnauthorizedHttpException
     */
    protected function getJwtAuthToken(string $tokenRaw): ?JwtToken
    {
        try {
            return $this->jwt->parseToken($tokenRaw, false, false);
        } catch (Exception $e) {
            $this->handleFailure('Refresh token is invalid or expired');
        }
    }

    /**
     * @param string $message
     * @throws UnauthorizedHttpException
     */
    protected function handleFailure(string $message):void
    {
        throw new UnauthorizedHttpException($message);
    }

    /**
     * Get raw token from HTTP request
     * @return string
     */
    protected abstract function getRawToken():string;

    /**
     * @param string $refreshToken
     * @param string $accessToken
     * @return array
     */
    protected function formatResponse(string $refreshToken, string $accessToken)
    {
        return [
            'access_token' =>  $accessToken,
            'refresh_token' =>  $refreshToken,
        ];
    }
}