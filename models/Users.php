<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "users".
 *
 * @property int $id
 * @property string $name
 * @property string $username
 * @property string $email
 * @property string $password
 * @property int $role_id
 * @property string|null $created_at
 * @property string|null $updated_at
 *
 * @property Roles $role
 * @property UserRefreshTokens[] $userRefreshTokens
 */
class Users extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'users';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['name', 'username', 'email', 'password', 'role_id'], 'required'],
            [['role_id'], 'integer'],
            [['created_at', 'updated_at'], 'safe'],
            [['name', 'username', 'email', 'password'], 'string', 'max' => 255],
            [['username'], 'unique'],
            [['email'], 'unique'],
            [['role_id'], 'exist', 'skipOnError' => true, 'targetClass' => Roles::className(), 'targetAttribute' => ['role_id' => 'id']],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'id' => 'ID',
            'name' => 'Name',
            'username' => 'Username',
            'email' => 'Email',
            'password' => 'Password',
            'role_id' => 'Role ID',
            'created_at' => 'Created At',
            'updated_at' => 'Updated At',
        ];
    }

    /**
     * Gets query for [[Role]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getRole()
    {
        return $this->hasOne(Roles::class, ['id' => 'role_id']);
    }

    /**
     * Gets query for [[UserRefreshTokens]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getUserRefreshTokens()
    {
        return $this->hasMany(UserRefreshTokens::class, ['urf_userID' => 'id']);
    }

    public static function findIdentityByAccessToken($token, $type = null)
    {
        return static::find()
            ->where(['userID' => (string) $token->getClaim('uid')])
            ->andWhere(['<>', 'usr_status', 'inactive'])  //adapt this to your needs
            ->one();
    }
    public function afterSave($isInsert, $changedOldAttributes)
    {
        // Purge the user tokens when the password is changed
        if (array_key_exists('usr_password', $changedOldAttributes)) {
            UserRefreshTokens::deleteAll(['urf_userID' => $this->userID]);
        }

        return parent::afterSave($isInsert, $changedOldAttributes);
    }
}
