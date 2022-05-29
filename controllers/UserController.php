<?php

namespace app\controllers;

use app\models\User;
use Yii;

/**
 * Default controller for the `v1` module
 */
class UserController extends BaseController
{
    // untuk verbs yg diperlukan misal get/put/patch/dsb
    protected function verbs()
    {
        return [
            'index' => ['GET'],
        ];
    }
    /**
     * Renders the index view for the module
     * @return string
     */
    public function actionIndex()
    {
        return  [
            'data' => User::find()->all(),
            'success' => true,
        ];;
    }
}
