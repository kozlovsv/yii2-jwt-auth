<?php

namespace kozlovsv\jwtauth;

use DomainException;
use Exception;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use InvalidArgumentException;
use yii\di\Instance;
use yii\filters\auth\AuthMethod;
use yii\web\Request;
use yii\web\UnauthorizedHttpException;

/**
 * JwtHttpBearerAuth is an action filter that supports the authentication method based on HTTP Bearer JWT token.
 * @package kozlovsv\jwtauth
 * @author Kozlov Sergey <kozlovsv78@gmail.com>
 */
class JwtHttpBearerAuth extends AuthMethod
{
    /**
     * @var string the HTTP header name
     */
    public $header = 'Authorization';
    /**
     * @var string a pattern to use to extract the HTTP authentication value
     */
    public $pattern = '/^Bearer\s+(.*?)$/';
    /**
     * @var string the HTTP authentication realm
     */
    public $realm = 'api';
    /**
     * @var string error message, sending in header when token is invalid
     */
    protected $errorDescription = 'The access token invalid or expired';
    /**
     * @var Jwt|string|array the [[Jwt]] object or the application component ID of the [[Jwt]].
     */
    public $jwt = 'jwt';

    /**
     * @inheritdoc
     */
    public function challenge($response)
    {
        $response->getHeaders()->set(
            'WWW-Authenticate',
            "Bearer realm=\"$this->realm\", error=\"invalid_token\", error_description=\"$this->errorDescription\""
        );
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate($user, $request, $response)
    {
        $tokenRaw = $this->extractJwtAuthTokenFromHeader($request);
        if ($tokenRaw) {
            $token = $this->getJwtAuthToken($response, $tokenRaw);
            $identity = $user->loginByAccessToken($token->getUserID(), get_class($this));
            if ($identity === null) {
                $this->challenge($response);
                $this->handleFailure($response);
            }
            return $identity;
        } else {
            $this->errorDescription = 'Token is empty';
            return null;
        }
    }

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        $this->jwt = Instance::ensure($this->jwt, Jwt::class);
    }

    /**
     * Create jwt auth token model from header
     *
     * @param $response
     * @param string $tokenRaw
     *
     * @return JwtToken|null
     * @throws UnauthorizedHttpException
     */
    protected function getJwtAuthToken($response, string $tokenRaw): ?JwtToken
    {
        try {
            return $this->jwt->parseToken($tokenRaw);
        } catch (DomainException|InvalidArgumentException|SignatureInvalidException $e) {
            $this->errorDescription = 'Invalid token format';
        } catch (BeforeValidException $e) {
            $this->errorDescription = 'Token has not expired';
        } catch (ExpiredException $e) {
            $this->errorDescription = 'Token expired';
        } catch (Exception $e) {
            $this->errorDescription = 'Bad token format';
        }
        $this->challenge($response);
        $this->handleFailure($response);
    }

    /**
     * Get raw token from header
     * @param Request $request
     * @return null|string
     */
    protected function extractJwtAuthTokenFromHeader(Request $request): ?string
    {
        $authHeader = $request->headers->get($this->header);
        if (!$authHeader) return null;
        if ($this->pattern !== null) {
            if (preg_match($this->pattern, $authHeader, $matches)) {
                return $matches[1] ?: null;
            } else {
                return null;
            }
        }
        return $authHeader;
    }
}