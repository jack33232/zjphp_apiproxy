<?php
namespace ZJPHP\ApiProxy\Facade;

use ZJPHP\Base\Facade;

class ApiProxy extends Facade
{
    /**
     * @inheritDoc
     */
    public static function getFacadeComponentId()
    {
        return 'apiProxy';
    }
}
