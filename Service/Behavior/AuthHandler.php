<?php
namespace ZJPHP\ApiProxy\Service\Behavior;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Behavior;
use ZJPHP\ApiProxy\Facade\ApiProxy;
use ZJPHP\ApiProxy\Protocol\RequestInterface;
use ZJPHP\Base\Kit\ArrayHelper;
use ZJPHP\Facade\Security;
use ZJPHP\Facade\ZJRedis;
use ZJPHP\Base\Exception\InvalidConfigException;

class AuthHandler extends Behavior
{
    public function authByJwt(RequestInterface $request)
    {
        $authentication = ZJPHP::$app->get('authentication');
        $auth_params = $request->getAuthParams();
        if (empty($auth_params['auth_system'])
            || empty($auth_params['audience'])
            || empty($auth_params['app_id'])
            || empty($auth_params['app_secret'])
        ) {
            throw new InvalidConfigException('No Enough data to apply JWT.');
        }

        $jwt_info = $this->getJwt($auth_params);

        if ($jwt_info['sign'] === 'Y') {
            $this->signData($request, $jwt_info['session_key']);
        }

        if ($jwt_info['encrypt'] === 'Y') {
            $this->encryptData($request, $jwt_info['session_key']);
        }

        $request->setHeaders([
            'Authorization' => $authentication->getJwtSchema() . ' ' . $jwt_info['jwt']
        ]);
    }

    protected function getJwt($auth_params)
    {
        $authentication = ZJPHP::$app->get('authentication');
        $jwt_cache_key = $this->getJwtCacheKey($auth_params['audience']);
        $redis_client = ZJRedis::connect();
        if ($redis_client->exists($jwt_cache_key)) {
            return $redis_client->hGetAll($jwt_cache_key);
        } else {
            $data_for_jwt = [
                'nonce' => Security::generateRandomString($auth_params['nonce_string_size']),
                'timer' => time(),
                'app_id' => $auth_params['app_id'],
                'audience' => $auth_params['audience']
            ];
            
            $data_for_jwt['signature'] = $authentication->sign($data_for_jwt, $auth_params['app_secret']);

            $jwt_data = ApiProxy::getRequest($auth_params['auth_system'], 'apply_jwt', [
                'POST' => $data_for_jwt
            ])->send();

            $jwt = $authentication->subVerifyJwt($jwt_data['jwt']);

            $expire_at = $jwt->getClaim('exp', strtotime('2047-06-30 23:59:59'));
            $data_to_cache = [
                'jwt' => (string) $jwt,
                'encrypt' => $jwt->getClaim('encrypt', 'N'),
                'sign' => $jwt->getClaim('sign', 'N')
            ];

            if (!empty($jwt_data['session_key'])) {
                $data_to_cache['session_key'] = $this->processSessionKey($jwt_data['session_key'], $auth_params['app_secret']);
            }

            $redis_client->hMSet($jwt_cache_key, $data_to_cache);

            return $data_to_cache;
        }
    }

    protected function processSessionKey($session_key, $app_secret)
    {
        $ciphertext = $session_key['ciphertext'];
        $encode = $session_key['encode'];
        $cipher = $session_key['cipher'];

        switch ($encode) {
            case 'base64':
                $ciphertext = base64_decode($ciphertext, true);
                break;
            case 'bin2hex':
                $ciphertext = hex2bin($ciphertext);
                break;
        }

        $cipher_bkp = Security::getCipher();
        Security::setCipher($cipher);
        $decrypted = Security::decryptByPassword($ciphertext, $app_secret);
        Security::setCipher($cipher_bkp);

        return $decrypted;
    }

    protected function getJwtCacheKey($audience)
    {
        return ZJPHP::$app->getAppName() . ':SubJwtPool:' . $audience;
    }

    protected function signData($request, $secret)
    {
        $authentication = ZJPHP::$app->get('authentication');
        //Only Post Data will be signed
        $data_to_sign = $request->getRequestParams('POST');
        $signature = $authentication->sign($data_to_sign, $secret);

        $request->setRequestParams([
            'POST' => [
                'signature' => $signature
            ]
        ]);
    }

    protected function encryptData($request, $secret)
    {
        //Sign before encrypted
        $data_to_encrypt = $request->getRequestParams('POST');
        if (ArrayHelper::isAssociative($data_to_encrypt)) {
            $new_post_data = Security::encryptByPassword(
                http_build_query($data_to_encrypt, '', '&', PHP_QUERY_RFC3986),
                $secret
            );

            $request->replaceRequestParams(['POST' => [
                'ciphertext' => base64_encode($new_post_data),
                'encode' => 'base64'
            ]]);
        }
    }

    public function authByRsaSign(RequestInterface $request)
    {
        $authentication = ZJPHP::$app->get('authentication');
        $request_params = $request->getRequestParams();
        $auth_params = $request->getAuthParams();
        $algo_id = $auth_params['algo'] ?? 'RS256';

        // Only sign both get & post & url
        $data_to_sign = ArrayHelper::merge($request_params['GET'], $request_params['POST']);
        $signature = $authentication->rsaSign($data_to_sign, $request->getTargetUrl(true), $algo_id);

        $request->setRequestParams([
            'POST' => [
                'signature' => $signature
            ]
        ]);
    }
}
