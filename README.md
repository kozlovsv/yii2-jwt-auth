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
        'class' => \kozlovsv\jwt\Jwt::class,
        'secretKey' => 'Your secret key',
        'alg' => 'HS256'; //signing algorithm to use
        'durationAccess' => 1800, //default 30 min
        'durationRefresh' => 1296000, //default 15 days
        'leeway' => 0; //clock skew
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
            'class' => \kozlovsv\jwt\JwtHttpBearerAuth::class,
        ];

        return $behaviors;
    }
}
```

Also you can use it with `CompositeAuth` reffer to a [doc](http://www.yiiframework.com/doc-2.0/guide-rest-authentication.html).