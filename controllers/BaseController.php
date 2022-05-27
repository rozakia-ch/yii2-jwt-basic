<?php

namespace app\controllers;

use sizeg\jwt\JwtHttpBearerAuth;
use yii\base\Controller;
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
        'Access-Control-Request-Method'    => ['*'],
        'Access-Control-Allow-Headers' =>  ['*']
      ],
    ];
    $behaviors['authenticator'] = [
      'class' => JwtHttpBearerAuth::class,
      'except' => [
        'login',
        'refresh-token',
        'options',
      ],
    ];

    return $behaviors;
  }
}
