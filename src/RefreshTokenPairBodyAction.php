<?php

namespace kozlovsv\jwtauth;

use yii\di\Instance;
use yii\web\Request;

/**
 * Action for refresh token pair Access token and refresh token
 * Get refresh token from HTTP body. When token sending by POST Request
 * @package kozlovsv\jwtauth
 * @author Kozlov Sergey <kozlovsv78@gmail.com>
 */
class RefreshTokenPairBodyAction extends RefreshTokenPairBlankAction
{

    /**
     * @var string the HTTP refresh token header name
     */
    public $headerRefresh = 'refresh_token';

    /**
     * @var Request|string request component name or instance
     */
    public $request = 'request';

    /**
     * @inheritdoc
     */
    public function init(): void
    {
        parent::init();
        $this->request   = Instance::ensure($this->request, Request::class);
    }

    /**
     * Get raw token from HTTP header
     * @return string
     */
    protected function getRawToken():string {
        return $this->request->getBodyParam($this->headerRefresh, '');
    }
}