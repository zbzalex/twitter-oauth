Twitter 1.0a oauth
==================


## Installation

```sh
php composer.phar require zbzalex/twitter-oauth-php
```

## Configuration
```php
$twitter = new \OAuth\Twitter\Twitter([
    'consumer_key' => '...',
    'consumer_secret' => '...',
    'callback_url' => 'http://localhost:8080/oauth/twitter'
]);
```

## Authorization
```php
session_start();

$tokenRequest = $twitter->getRequestToken();

$_SESSION['oauth_token_secret'] = $tokenRequest['request_token_secret'];

$authorizationUrl = $twitter->getOauthVerifier($tokenRequest['request_token']);

header(sprintf("Location: %s", $authorizationUrl), true);
```

## Authentication
```php
if (!empty($_GET["oauth_verifier"]) && !empty($_GET["oauth_token"]) && isset($_SESSION["oauth_token_secret"])) {

            $oauthTokenSecret = $_SESSION["oauth_token_secret"];

            $twitterUser = $twitter->getUserData($_GET["oauth_verifier"], $_GET["oauth_token"], $oauthTokenSecret);
            $twitterUser = json_decode($twitterUser, true);

            if (!empty($twitterUser)) {
                // ...
            }
}
```
