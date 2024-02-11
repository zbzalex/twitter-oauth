<?php

namespace OAuth\Twitter;

/**
 * Twitter 1.0a oauth
 * 
 * @author Christian Fei
 * @author Sasha Broslavskiy <sasha.broslavskiy@gmail.com>
 */
class Twitter
{
    private $consumerKey;
    private $consumerSecret;
    private $signatureMethod = 'HMAC-SHA1';
    private $oauthVersion = '1.0';
    //private $http_status = "";
    private $callbackUrl;

    public function __construct(array $options = [])
    {
        $this->consumerKey = $options['consumer_key'];
        $this->consumerSecret = $options['consumer_secret'];
        $this->callbackUrl = $options['callback_url'];
    }

    public function getOauthVerifier($requestToken)
    {
        $requestResponse = $this->getRequestToken();
        $authUrl = "https://api.twitter.com/oauth/authenticate";
        $redirectUrl = $authUrl . "?oauth_token=" . $requestToken;

        return $redirectUrl;
    }

    public function getRequestToken()
    {
        $url = "https://api.twitter.com/oauth/request_token";

        $params = array(
            'oauth_callback' => $this->callbackUrl,
            "oauth_consumer_key" => $this->consumerKey,
            "oauth_nonce" => base64_encode(random_bytes(32)),
            "oauth_signature_method" => $this->signatureMethod,
            "oauth_timestamp" => time(),
            "oauth_version" => $this->oauthVersion
        );

        $params['oauth_signature'] = $this->createSignature('POST', $url, $params);

        $oauthHeader = $this->generateOauthHeader($params);

        $response = $this->curlHttp('POST', $url, $oauthHeader);

        $responseVariables = array();
        parse_str($response, $responseVariables);

        $tokenResponse = array();

        $tokenResponse["request_token"] = $responseVariables["oauth_token"];
        $tokenResponse["request_token_secret"] = $responseVariables["oauth_token_secret"];

        return $tokenResponse;
    }

    public function getAccessToken($oauthVerifier, $oauthToken, $oauthTokenSecret)
    {
        $url = 'https://api.twitter.com/oauth/access_token';

        $oauthPostData = array(
            'oauth_verifier' => $oauthVerifier
        );

        $params = array(
            "oauth_consumer_key" => $this->consumerKey,
            "oauth_nonce" => base64_encode(random_bytes(32)),
            "oauth_signature_method" => $this->signatureMethod,
            "oauth_timestamp" => time(),
            "oauth_token" => $oauthToken,
            "oauth_version" => $this->oauthVersion
        );

        $params['oauth_signature'] = $this->createSignature('POST', $url, $params, $oauthTokenSecret);

        $oauthHeader = $this->generateOauthHeader($params);

        $response = $this->curlHttp('POST', $url, $oauthHeader, $oauthPostData);
        
        $responseVariables = array();
        parse_str($response, $responseVariables);

        $tokenResponse = array();
        $tokenResponse["access_token"] = $responseVariables["oauth_token"];
        $tokenResponse["access_token_secret"] = $responseVariables["oauth_token_secret"];

        return $tokenResponse;
    }

    public function getUserData($oauthVerifier, $oauthToken, $oauthTokenSecret)
    {
        $accessTokenResponse = $this->getAccessToken($oauthVerifier, $oauthToken, $oauthTokenSecret);

        $url = 'https://api.twitter.com/1.1/account/verify_credentials.json';

        $params = array(
            "oauth_consumer_key" => $this->consumerKey,
            "oauth_nonce" => base64_encode(random_bytes(32)),
            "oauth_signature_method" => $this->signatureMethod,
            "oauth_timestamp" => time(),
            "oauth_token" => $accessTokenResponse["access_token"],
            "oauth_version" => $this->oauthVersion
        );

        $params['oauth_signature'] = $this->createSignature('GET', $url, $params, $accessTokenResponse["access_token_secret"]);

        $oauthHeader = $this->generateOauthHeader($params);

        $response = $this->curlHttp('GET', $url, $oauthHeader);

        return $response;
    }

    public function curlHttp($httpRequestMethod, $url, $oauthHeader, $post_data = null)
    {
        $ch = curl_init();

        $headers = array(
            "Authorization: OAuth " . $oauthHeader
        );

        $options = [
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HEADER => false,
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
        ];
        if ($httpRequestMethod == 'POST') {
            $options[CURLOPT_POST] = true;
        }
        if (!empty($post_data)) {
            $options[CURLOPT_POSTFIELDS] = $post_data;
        }
        curl_setopt_array($ch, $options);
        $response = curl_exec($ch);

        //$this->http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return $response;
    }

    public function generateOauthHeader($params)
    {
        foreach ($params as $k => $v) {

            $oauthParamArray[] = $k . '="' . rawurlencode($v) . '"';
        }
        $oauthHeader = implode(', ', $oauthParamArray);

        return $oauthHeader;
    }

    public function createSignature($httpRequestMethod, $url, $params, $tokenSecret = '')
    {
        $strParams = rawurlencode(http_build_query($params));

        $baseString = $httpRequestMethod . "&" . rawurlencode($url) . "&" . $strParams;

        $signKey = $this->generateSignatureKey($tokenSecret);
        $oauthSignature = base64_encode(hash_hmac('sha1', $baseString, $signKey, true));

        return $oauthSignature;
    }

    public function generateSignatureKey($tokenSecret)
    {
        $signKey = rawurlencode($this->consumerSecret) . "&";
        if (!empty($tokenSecret)) {
            $signKey = $signKey . rawurlencode($tokenSecret);
        }
        return $signKey;
    }
}
