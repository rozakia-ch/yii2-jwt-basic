<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "user_refresh_tokens".
 *
 * @property int $user_refresh_tokenID
 * @property int $urf_userID
 * @property string $urf_token
 * @property string $urf_ip
 * @property string $urf_user_agent
 * @property string $created_at
 * @property string $updated_at
 *
 * @property Users $urfUser
 */
class UserRefreshToken extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'user_refresh_tokens';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['urf_userID', 'urf_token', 'urf_ip', 'urf_user_agent'], 'required'],
            [['urf_userID'], 'integer'],
            [['created_at', 'updated_at'], 'safe'],
            [['urf_token', 'urf_user_agent'], 'string', 'max' => 1000],
            [['urf_ip'], 'string', 'max' => 50],
            [['urf_userID'], 'exist', 'skipOnError' => true, 'targetClass' => User::class, 'targetAttribute' => ['urf_userID' => 'id']],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'user_refresh_tokenID' => 'User Refresh Token ID',
            'urf_userID' => 'Urf User ID',
            'urf_token' => 'Urf Token',
            'urf_ip' => 'Urf Ip',
            'urf_user_agent' => 'Urf User Agent',
            'created_at' => 'Created At',
            'updated_at' => 'Updated At',
        ];
    }

    /**
     * Gets query for [[UrfUser]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getUrfUser()
    {
        return $this->hasOne(User::class, ['id' => 'urf_userID']);
    }
}
