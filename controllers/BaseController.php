<?php

namespace app\controllers;

use sizeg\jwt\JwtHttpBearerAuth;
use yii\rest\Controller;
use yii\filters\Cors;

abstract class BaseController extends Controller
{
  public function behaviors()
  {
    $behaviors = parent::behaviors();
    $behaviors['corsFilter'] = [
      'class' => Cors::class,
      'cors' => [
        'Origin' => ['*'],
        'Access-Control-Request-Method' => ['GET', 'POST', 'PUT', 'OPTIONS'],
        'Access-Control-Request-Headers' => ['*'],
        'Access-Control-Allow-Credentials' => true,
      ],
    ];
    $behaviors['authenticator'] = [
      'class' => JwtHttpBearerAuth::class,
      'optional' => [
        'login',
        'refresh-token',
        // 'options',
      ],
    ];

    return $behaviors;
  }
}
