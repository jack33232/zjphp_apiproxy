<?php
namespace ZJPHP\ApiProxy\Service\Protocol;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Facade\HttpClient;
use ZJPHP\Base\Kit\ArrayHelper;
use ZJPHP\Base\Kit\StringHelper;
use ZJPHP\Base\Exception\InvalidConfigException;
use ZJPHP\Base\Exception\InvalidParamException;
use ZJPHP\ApiProxy\Facade\ApiProxy;
use ZJPHP\ApiProxy\Base\Exception\ApiProxyException;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\RequestException;
use Exception;

class Http extends Component implements RequestInterface
{
    private $_requestConfig = [];

    public $protocol;
    public $version;

    protected $targetUrl = "{PATH}";
    protected $baseUrl = "{SCHEME}://{HOST}{PORT}{BASE_PATH}";
    protected $authType = null;
    protected $method = 'GET';
    protected $contentType = 'application/x-www-form-urlencoded';
    protected $connectionTimeout = 0; // Default no timeout
    protected $veriy = null;
    protected $timeout = 0;
    protected $getParams = [];
    protected $postParams = [];
    protected $urlParams = [];
    protected $authParams = [];
    protected $stream = false;

    protected $allowedAuthType = [
        // TBD to add more types of auth
        'jwt',
        'rsa_sign'
    ];

    protected $allowedContentType = [
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'application/json'
    ];

    protected $allowedMethod = [
        'GET',
        'POST',
        'DELETE',
        'PUT',
        'HEAD',
        'PATCH'
    ];

    public function init()
    {
        if (filter_var($this->baseUrl, FILTER_VALIDATE_URL) === false) {
            throw new InvalidConfigException('Invalid Format of Base URL: ' . $this->baseUrl);
        }
        // Prepare the target url
        $this->processUrl();

        // Validate the complete url
        $full_target_url = $this->baseUrl . $this->targetUrl;
        if (filter_var($full_target_url, FILTER_VALIDATE_URL) === false) {
            throw new InvalidConfigException('Invalid Format of Full Target URL: ' . $full_target_url);
        }

        switch ($this->contentType) {
            case 'application/json';
            case 'application/x-www-form-urlencoded':
                if (!empty($this->postParams) && !ArrayHelper::isAssociative($this->postParams)) {
                    throw new InvalidParamException('Incorrect format of POST data.');
                }
                break;
            case 'multipart/form-data':
                if (empty($this->postParams)) {
                    break;
                }
                if (ArrayHelper::isAssociative($this->postParams)) {
                    throw new InvalidParamException('Incorrect format of Form POST data.');
                }
                foreach ($this->postParams as $item) {
                    if (empty($item['name']) || empty($item['content'])) {
                        throw new InvalidParamException('Incorrect format of Multipart POST data.');
                    }
                }
                break;
            default:
                if (!is_string($this->postParams) || !is_resource($this->postParams)) {
                    throw new InvalidParamException('Incorrect format of Raw POST data.');
                }
                break;
        }
    }

    protected function processUrl()
    {
        if (!empty($this->urlParams)) {
            $this->targetUrl = strtr($this->targetUrl, $this->urlParams);
        }
    }

    protected function processParams()
    {
        // GET Params
        if (!empty($this->getParams)) {
            $this->_requestConfig['query'] = $this->getParams;
        }
        // POST Paras
        if (!empty($this->postParams)) {
            switch ($this->contentType) {
                case 'application/x-www-form-urlencoded':
                    unset($this->_requestConfig['multipart']);
                    unset($this->_requestConfig['body']);
                    $this->_requestConfig['form_params'] = $this->postParams;
                    break;
                case 'multipart/form-data':
                    unset($this->_requestConfig['form_params']);
                    unset($this->_requestConfig['body']);
                    $this->_requestConfig['multipart'] = $this->postParams;
                    break;
                case 'application/json':
                    unset($this->_requestConfig['multipart']);
                    unset($this->_requestConfig['form_params']);
                    $this->_requestConfig['body'] = json_encode($this->postParams, JSON_NUMERIC_CHECK);
                    break;
                default:
                    unset($this->_requestConfig['multipart']);
                    unset($this->_requestConfig['form_params']);
                    $this->_requestConfig['body'] = $this->postParams;
                    break;
            }
        }
    }

    public function send()
    {
        try {
            // Handler Auth
            $this->processAuth();
            // Init a http client
            $this->processParams();
            $config = [
                'connection_timeout' => $this->connectionTimeout,
                'timeout' => $this->timeout,
                'stream' => $this->stream
            ];

            if (!is_null($this->veriy)) {
                $config['verify'] = $this->veriy;
            }
            $http_client = HttpClient::instance($config);
            $target_url = $this->getTargetUrl(true);
            $response = $http_client->request($this->method, $target_url, $this->_requestConfig);

            return $this->processResponse($response);
        } catch (Exception $e) {
            $reformed_exception = $this->processException($e);
            throw $reformed_exception;
        }
    }

    protected function processException(Exception $original_exception)
    {
        $e = $original_exception;
        if ($original_exception instanceof RequestException) {
            if ($original_exception->hasResponse()) {
                $response = $original_exception->getResponse();
                $response_content = $this->processResponse($response);
                $e = new ApiProxyException(
                    $response->getReasonPhrase(),
                    $response->getStatusCode(),
                    $original_exception,
                    $response_content
                );
            }
        }

        return $e;
    }

    protected function processAuth()
    {
        if (!empty($this->authType)) {
            $api_proxy = ZJPHP::$app->get('apiProxy');
            $handler_name = 'authBy' . StringHelper::studly($this->authType);
            $api_proxy->$handler_name($this);
        }
    }

    protected function processResponse($response)
    {
        $body = $response->getBody();
        $headers = $response->getHeaders();
        if ($response->hasHeader('Content-Type')) {
            $api_proxy = ZJPHP::$app->get('apiProxy');
            $content_type = $response->getHeader('Content-Type')[0];

            switch ($content_type) {
                case 'text/json':
                case 'application/json':
                    $handler_name = 'decode' . ($this->stream ? 'Stream' : '') . 'Json';
                    return $api_proxy->$handler_name($headers, $body);
                    break;
                case 'text/xml':
                case 'application/xml':
                    // TBD
                    break;
                case 'application/octet-stream':
                    // TBD
                    break;
                default:
                    return $body->getContents();
                    break;
            }
        } else {
            return $body->getContents();
        }
    }

    public function setHeaders(array $headers)
    {
        $as_is = $this->_requestConfig['headers'] ?? [];
        $this->_requestConfig['headers'] = ArrayHelper::merge($as_is, $headers);
    }

    public function setCookie(CookieJar $jar)
    {
        $this->_requestConfig['cookie'] = $jar;
    }

    public function getCookie()
    {
        return $this->_requestConfig['cookie'] ?? null;
    }

    public function setScheme(string $scheme)
    {
        $this->baseUrl = str_replace('{SCHEME}', $scheme, $this->baseUrl);
    }

    public function setHost(string $host)
    {
        $this->baseUrl = str_replace('{HOST}', $host, $this->baseUrl);
    }

    public function setBasePath(string $base_path)
    {
        if (!empty($base_path) && strpos($base_path, '/', 0) !== 0) {
            $base_path = '/' . $base_path;
        }

        $this->baseUrl = rtrim(str_replace('{BASE_PATH}', $base_path, $this->baseUrl), '/');
    }

    public function setPort($port)
    {
        if ($port === 80 || $port === 443) {
            $port = '';
        } else {
            $port = ':' . $port;
        }

        $this->baseUrl = str_replace('{PORT}', $port, $this->baseUrl);
    }

    public function setPath(string $path)
    {
        if (!empty($path) && strpos($path, '/', 0) !== 0) {
            $path = '/' . $path;
        }

        $this->targetUrl = rtrim(str_replace('{PATH}', $path, $this->targetUrl), '/');
    }

    public function setAuthType(string $auth_type)
    {
        if (!empty($auth_type)) {
            $auth_type = strtolower($auth_type);
            if (!in_array($auth_type, $this->allowedAuthType)) {
                throw new InvalidConfigException('Auth Type: ' . $auth_type . ' is not supported.');
            }

            $this->authType = $auth_type;
        }
    }

    public function getAuthType()
    {
        return $this->authType;
    }

    public function setMethod(string $method)
    {
        $method = strtoupper($method);
        if (!in_array($method, $this->allowedMethod)) {
            throw new InvalidConfigException('Method:' . $method . ' is not supported.');
        }

        $this->method = $method;
    }

    public function setContentType(string $content_type)
    {
        if (!in_array($content_type, $this->allowedContentType)) {
            throw new InvalidConfigException('Method:' . $method . ' is not supported.');
        }
        $this->contentType = $content_type;
    }

    public function setConnectionTimeout(float $timeout)
    {
        $this->connectionTimeout = ($timeout < 60 && $timeout > 0) ? $timeout : 0;
    }

    public function setTimeout(float $timeout)
    {
        $this->timeout = ($timeout < 60 && $timeout > 0) ? $timeout : 0;
    }

    public function setVerify($verify)
    {
        if (is_string($verify) && !file_exists($veriy)) {
            throw new InvalidConfigException('The CA bundle not found.');
        }

        $this->veriy = $verify;
    }

    public function setRequestParams($params)
    {
        foreach ($params as $type => $sub_params) {
            $type = strtoupper($type);
            switch ($type) {
                case 'GET':
                    $this->getParams = ArrayHelper::merge($this->getParams, $sub_params);
                    break;
                case 'POST':
                    $this->postParams = ArrayHelper::merge($this->postParams, $sub_params);
                    break;
                case 'URL':
                    $this->urlParams = ArrayHelper::merge($this->urlParams, $sub_params);
                    break;
            }
        }
    }

    public function replaceRequestParams($params)
    {
        foreach ($params as $type => $sub_params) {
            $type = strtoupper($type);
            switch ($type) {
                case 'GET':
                    $this->getParams = $sub_params;
                    break;
                case 'POST':
                    $this->postParams = $sub_params;
                    break;
                case 'URL':
                    $this->urlParams = $sub_params;
                    break;
            }
        }
    }

    public function getRequestParams($mask = ['GET', 'POST', 'URL'])
    {
        if ($single_flag = is_string($mask)) {
            $mask = [$mask];
        }
        $result = ArrayHelper::mask($mask, [
            'GET' => $this->getParams,
            'POST' => $this->postParams,
            'URL' => $this->urlParams
        ]);

        return $single_flag ? reset($result) : $result;
    }

    public function setAuthParams($auth_params)
    {
        if (!empty($auth_params)) {
            $this->authParams = $auth_params;
        }
    }

    public function getAuthParams()
    {
        return $this->authParams;
    }

    public function getBaseUrl()
    {
        return $this->baseUrl;
    }

    public function getTargetUrl($full_target_url = false)
    {
        if ($full_target_url) {
            return $this->baseUrl . $this->targetUrl;
        } else {
            return $this->targetUrl;
        }
    }

    public function setStream(bool $stream)
    {
        $this->stream = $stream;
    }
}
