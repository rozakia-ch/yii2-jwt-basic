<?php

namespace app\controllers;

use app\models\LoginForm;
use app\models\User;
use app\models\UserRefreshToken;
use Yii;

use yii\web\HttpException;

/**
 * Default controller for the `v1` module
 */
class AuthController extends BaseController
{
  // untuk verbs yg diperlukan misal get/put/patch/dsb
  protected function verbs()
  {
    return [
      'register' => ['POST'],
      'login' => ['POST'],
      'data' => ['GET'],
    ];
  }
  //fungsi untuk login
  public function actionLogin()
  {
    $model = new LoginForm();
    if ($model->load(Yii::$app->getRequest()->getBodyParams(), '') && $model->login()) {
      $userData = User::find()->asArray()
        ->with("role")
        ->where(['id' => Yii::$app->user->identity->id])
        ->one();
      $response = [
        'success' => true,
        'message' => 'login berhasil!',
        'user' => $userData,
        'token' => User::generateJwt(Yii::$app->user->identity->id),
        'refreshToken' => User::generateRefreshToken(Yii::$app->user->identity->id)->urf_token,
      ];
      return $response;
    } else {
      $model->validate();
      return [
        'success' => false,
        'data' => $model
      ];
    }
  }
  //fungsi untuk register
  public function actionRegister()
  {
    $mUser = new User();

    if (!Yii::$app->request->post('password') || !Yii::$app->request->post('email') || !Yii::$app->request->post('username'))
      throw new HttpException(400, 'Check collumn required');

    $username = Yii::$app->request->post('username');
    $password = Yii::$app->request->post('password');
    $email = Yii::$app->request->post('email');

    if (User::findOne(['username' => $username]))
      throw new HttpException(500, 'Username is already registered');

    if (User::findOne(['email' => $email]))
      throw new HttpException(500, 'Email is already registered');
    $mUser->name = Yii::$app->request->post('name');
    $mUser->username = $username;
    $mUser->email = $email;
    $mUser->password = $hash = Yii::$app->getSecurity()->generatePasswordHash($password);
    $mUser->role_id = Yii::$app->request->post('roleID');
    $mUser->auth_key = Yii::$app->security->generateRandomString();
    $mUser->save();
    return $mUser;
  }
  // fungsi untuk refresh-token
  public function actionRefreshToken()
  {
    // $refreshToken = Yii::$app->request->cookies->getValue('refresh-token', false);

    $refreshToken = Yii::$app->request->headers['refresh-token'];
    if (!$refreshToken) {
      return new \yii\web\UnauthorizedHttpException('No refresh token found.');
    }

    $userRefreshToken = UserRefreshToken::findOne(['urf_token' => $refreshToken]);

    if (Yii::$app->request->getMethod() == 'POST') {
      // Getting new JWT after it has expired
      if (!$userRefreshToken) {
        return new \yii\web\UnauthorizedHttpException('The refresh token no longer exists.');
      }

      $user = User::find()  //adapt this to your needs
        ->where(['id' => $userRefreshToken->urf_userID])
        // ->andWhere(['not', ['usr_status' => 'inactive']])
        ->one();
      if (!$user) {
        $userRefreshToken->delete();
        return new \yii\web\UnauthorizedHttpException('The user is inactive.');
      }

      $token = User::generateJwt($user->id);

      return [
        'status' => 'ok',
        'token' => (string) $token,
      ];
    } elseif (Yii::$app->request->getMethod() == 'DELETE') {
      // Logging out
      if ($userRefreshToken && !$userRefreshToken->delete()) {
        return new \yii\web\ServerErrorHttpException('Failed to delete the refresh token.');
      }

      return ['status' => 'ok'];
    } else {
      return new \yii\web\UnauthorizedHttpException('The user is inactive.');
    }
  }
  //hanya untuk tes token
  public function actionData()
  {
    return [
      'data' => User::find()->all(),
      'success' => true,
    ];
  }
}
