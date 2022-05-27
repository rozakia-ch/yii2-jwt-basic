<?php

namespace app\controllers;

use Yii;
use app\models\UserRefreshTokens;
use app\models\Users;
use yii\filters\Cors;
use Exception;
use yii\web\HttpException;

class AuthController extends \yii\web\Controller
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
            'class' => \sizeg\jwt\JwtHttpBearerAuth::class,
            'except' => [
                'login',
                'refresh-token',
                'options',
            ],
        ];

        return $behaviors;
    }
    private function generateJwt(Users $user)
    {
        $jwt = Yii::$app->jwt;
        $signer = $jwt->getSigner('HS256');
        $key = $jwt->getKey();
        $time = time();

        $jwtParams = Yii::$app->params['jwt'];

        return $jwt->getBuilder()
            ->issuedBy($jwtParams['issuer'])
            ->permittedFor($jwtParams['audience'])
            ->identifiedBy($jwtParams['id'], true)
            ->issuedAt($time)
            ->expiresAt($time + $jwtParams['expire'])
            ->withClaim('uid', $user->id)
            ->getToken($signer, $key);
    }

    /**
     * @throws yii\base\Exception
     */
    private function generateRefreshToken(Users $user, Users $impersonator = null): UserRefreshTokens
    {
        $refreshToken = Yii::$app->security->generateRandomString(200);

        // TODO: Don't always regenerate - you could reuse existing one if user already has one with same IP and user agent
        $userRefreshToken = new UserRefreshTokens([
            'urf_userID' => $user->id,
            'urf_token' => $refreshToken,
            'urf_ip' => Yii::$app->request->userIP,
            'urf_user_agent' => Yii::$app->request->userAgent,
            'urf_created' => gmdate('Y-m-d H:i:s'),
        ]);
        if (!$userRefreshToken->save()) {
            throw new \yii\web\ServerErrorHttpException('Failed to save the refresh token: ' . $userRefreshToken->getErrorSummary(true));
        }

        // Send the refresh-token to the user in a HttpOnly cookie that Javascript can never read and that's limited by path
        Yii::$app->response->cookies->add(new \yii\web\Cookie([
            'name' => 'refresh-token',
            'value' => $refreshToken,
            'httpOnly' => true,
            'sameSite' => 'none',
            'secure' => true,
            'path' => '/v1/auth/refresh-token',  //endpoint URI for renewing the JWT token using this refresh-token, or deleting refresh-token
        ]));

        return $userRefreshToken;
    }
    public function actionLogin()
    {
        if (!Yii::$app->request->post('password') || !Yii::$app->request->post('username'))
            throw new yii\web\HttpException(401, 'Check input username & password');

        $username = Yii::$app->request->post('username');
        $password = Yii::$app->request->post('password');
        try {
            $user = Users::findOne(['username' => $username]);
            if (!$user)
                throw new HttpException(401, 'Check username & password');

            if (!password_verify($password, $user->password))
                throw new HttpException(401, 'Check username & password');

            $token = $this->generateJwt($user);
            $this->generateRefreshToken($user);
            // $user = Users::find()->asArray()->with("contact")->all();
            $userData = Users::find()->asArray()
                ->with(["userRefreshTokens", "role"])
                ->where(['id' => $user->id])
                ->one();

            return [
                'user' => $userData,
                'token' => (string) $token,
            ];
        } catch (Exception $e) {
            throw new HttpException(500, $e);
        }
    }
    public function actionRefreshToken()
    {
        // $refreshToken = Yii::$app->request->cookies->getValue('refresh-token', false);

        $refreshToken = Yii::$app->request->headers['refresh-token'];
        if (!$refreshToken) {
            return new \yii\web\UnauthorizedHttpException('No refresh token found.');
        }

        $userRefreshToken = UserRefreshTokens::findOne(['urf_token' => $refreshToken]);

        if (Yii::$app->request->getMethod() == 'POST') {
            // Getting new JWT after it has expired
            if (!$userRefreshToken) {
                return new \yii\web\UnauthorizedHttpException('The refresh token no longer exists.');
            }

            $user = Users::find()  //adapt this to your needs
                ->where(['id' => $userRefreshToken->urf_userID])
                // ->andWhere(['not', ['usr_status' => 'inactive']])
                ->one();
            if (!$user) {
                $userRefreshToken->delete();
                return new \yii\web\UnauthorizedHttpException('The user is inactive.');
            }

            $token = $this->generateJwt($user);

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
}
