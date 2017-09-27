<?php
namespace ZJPHP\ApiProxy\Service\Behavior;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Behavior;
use ZJPHP\ApiProxy\Exception\ApiProxyException;

class ResponseHandler extends Behavior
{
    public function decodeJson($headers, $body)
    {
        $response_content = json_decode($body->getContents(), true);
        $msg = trim(json_last_error_msg());

        if (strtolower($msg) !== 'no error') {
            throw new ApiProxyException('Unable to decode response content with error - ' . $msg);
        }

        return $response_content;
    }

    public function decodeStreamJson($headers, $body)
    {
        // TBD
    }
}
