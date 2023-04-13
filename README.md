# yii2-jwt-auth

The library implements authorization through the JWT token.

When authorizing, two tokens are used: a refresh token and an access token.Access token is short-lived reusable, refresh token is long-lived one-time.

The application cache component (`Yii::$app->cache`) is used to store tokens, tokens are not saved to the database.
Only the token ID is stored, a unique MD5 cache. Therefore it is safe. Refresh token storage is used to reissue an access token.


Storage of access tokens is used as a whitelist of tokens, if the stored token is not in the list, authorization will not pass, even if the token has a valid signature and expiration date


## Installation

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```bash
php composer.phar require --prefer-dist kozlovsv/yii2-jwt-auth "@dev"
```

or add

```
"kozlovsv/yii2-jwt-auth": "@dev"
```

to the require section of your `composer.json` file.

## Dependencies

- PHP 7.2+
- [firebase/php-jwt 6.0+](https://github.com/firebase/php-jwt)

## Basic usage

Add `jwt` component to your configuration file,

```php
'components' => [
    'jwt' => [
        'class' => \kozlovsv\jwtauth\Jwt::class,
        'accessTokenSecret' => 'Your access token secret',
        'refreshTokenSecret' => 'Your refresh token secret', //Not equal to access secret
        'alg' => 'HS256', //signing algorithm to use
        'durationAccess' => 1800, //default 30 min
        'durationRefresh' => 1296000, //default 15 days
        'leeway' => 0, //clock skew
    ],
],
```

Configure the `authenticator` behavior as follows.

```php
namespace app\controllers;

class ExampleController extends \yii\rest\Controller
{

    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        $behaviors = parent::behaviors();
        $behaviors['authenticator'] = [
            'class' => \kozlovsv\jwtauth\JwtHttpBearerAuth::class,
        ];

        return $behaviors;
    }
}
```

Also you can use it with `CompositeAuth` reffer to a [doc](http://www.yiiframework.com/doc-2.0/guide-rest-authentication.html).

## Yii2 basic template example

### Basic scheme
The authentication scheme is based on this [specification](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5).

1. Client send credentials. For example, login + password. In our example, this is a POST request to https://your-domain/rest/login. 
2. Backend validate them
3. If credentials is valid client receive pair token: refresh and access
4. Client store tokens for the future requests
5. Сlient sends a request to the backend using a access token for authentication. In our example, this is a request to https://your-domain/rest/data. In the header of the request section, you must specify the header `Authorization: Bearer YOUR_ACCESS_TOKEN`
6. If access token is expired, backent send response with 401 HTTP status
7. Client send query with refresh token, for renew pair tokens. In our example, this is a POST request to https://your-domain/rest/refresh-token. Post parameter name for refresh token is `refresh_token='Your refresh token'`
8. If refresh token is invalid, go to step 1

### Step-by-step usage example

1. Install component

    ```bash
    php composer.phar require --prefer-dist kozlovsv/yii2-jwt-auth "@dev"
    ```

2. Add to config/web.php into `components` section

    ```php
    $config = [
        'components' => [
            // other default components here..
            'jwt' => [
                'class' => \kozlovsv\jwtauth\Jwt::class,
                'accessTokenSecret' => 'Your access token secret',
                'refreshTokenSecret' => 'Your refresh token secret', //Not equal to access secret
                'alg' => 'HS256', //signing algorithm to use
                'durationAccess' => 1800, //default 30 min
                'durationRefresh' => 1296000, //default 15 days
                'leeway' => 0, //clock skew
            ],
        ],
    ];
    ```
3. Change method `app\models\User::findIdentityByAccessToken()`

    ```php
    /**
     * @param int $token User id
     * @inheritdoc
     */
    public static function findIdentityByAccessToken($token, $type = null)
    {
        $user = self::findOne((int) $token);
        if ($user) return $user;
        return null;
    }
    ```

4. Create controller

    ```php
    <?php
    
    namespace app\controllers;
    
    use kozlovsv\jwtauth\Jwt;
    use kozlovsv\jwtauth\RefreshTokenPairBodyAction;
    use Yii;
    use yii\web\UnauthorizedHttpException;
    
    class RestController extends Controller
    {
        /**
         * @inheritdoc
         */
        public function behaviors()
        {
            $behaviors = parent::behaviors();
            $behaviors['authenticator'] = [
                'class' => \kozlovsv\jwtauth\JwtHttpBearerAuth::class,
                'optional' => [
                    'rest/login',
                    'rest/refresh-token'
                ],
            ];
            return $behaviors;
        }
   
        public function actions()
        {
            //Add to refresh token pair action
            return [
                'refresh-token' => RefreshTokenPairBodyAction::class,
            ];
        }
   
        /**
          * @return \yii\web\Response
          * @throws UnauthorizedHttpException
          * @throws \yii\base\InvalidConfigException
          */
        public function actionLogin() {
            $model = new \app\models\form\LoginForm([
                'rememberMe' => false,
            ]);
            if ($model->load(Yii::$app->request->getBodyParams(), '') && $model->login()) {
                $user = Yii::$app->user->identity;

                /** @var Jwt $jwtServ */
                $jwtServ = Yii::$app->get('jwt');
                list($refreshToken, $acsessToken) = $jwtServ->generateAndSavePairTokens($user->getId());
                return $this->asJson([
                    'user_id' => $user->getId(),
                    'access_token' =>  $acsessToken,
                    'refresh_token' =>  $refreshToken,
                   ]);
            }
            throw new UnauthorizedHttpException('Your request was made with invalid credentials. ' . implode(',', $model->getFirstErrors()));
        }
    
        /**
         * @return \yii\web\Response
         */
        public function actionData()
        {
            return $this->asJson([
                'success' => true,
            ]);
        }
    }
    ```