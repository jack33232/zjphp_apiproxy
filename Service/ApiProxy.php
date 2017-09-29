<?php
namespace ZJPHP\ApiProxy\Service;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Base\Exception\InvalidConfigException;
use ZJPHP\Base\Exception\InvalidCallException;
use ZJPHP\Base\Exception\InvalidParamException;
use ZJPHP\Base\Exception\DatabaseErrorException;
use Klein\Exceptions\HttpException;
use ZJPHP\Base\Kit\StringHelper;

class ApiProxy extends Component
{
    protected $apiMap = [];

    public function hasService($system, $service_name)
    {
        return isset($this->apiMap[$system]['service_list'][$service_name]);
    }

    public function getRequest($system, $service_name, $request_params)
    {
        if (!isset($this->apiMap[$system]['service_list'][$service_name])) {
            throw new InvalidConfigException('Request service has not be set.');
        }

        $service_setting = $this->apiMap[$system]['service_list'][$service_name];
        $service_setting['host'] = $this->apiMap[$system]['host'];
        $service_setting['base_path'] = $this->apiMap[$system]['base_path'];
        $service_setting['request_params'] = $request_params;

        $protocol = $service_setting['protocol'];
        $request_name = __NAMESPACE__ . '\\Protocol\\' . StringHelper::studly($protocol) . 'Protocol';

        $definition = ['class' => $request_name] + $service_setting;
        return ZJPHP::createObject($definition);
    }

    public function setApiMap($map)
    {
        // TBD add method to validate the setting
        $this->apiMap = $map;
    }
}
