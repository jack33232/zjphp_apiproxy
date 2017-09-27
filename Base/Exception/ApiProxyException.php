<?php
namespace ZJPHP\ApiProxy\Base\Exception;

use Exception;

class ApiProxyException extends Exception
{
    protected $responseContent;

    public function __construct($message, $code = 0, $previous_exception = null, $response_content = null)
    {
        parent::__construct($message, $code, $previous_exception);
        $this->responseContent = $response_content;
    }

    public function getResponseContent()
    {
        return $this->responseContent;
    }
}
