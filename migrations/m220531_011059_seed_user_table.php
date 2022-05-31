<?php

use yii\db\Migration;

/**
 * Class m220531_011059_seed_user_table
 */
class m220531_011059_seed_user_table extends Migration
{
    /**
     * {@inheritdoc}
     */
    public function safeUp()
    {
        $this->insert(
            'users',
            [
                'name' => 'Administrator',
                'username' => 'admin',
                'email' => 'admin@mail.com',
                'password' => Yii::$app->getSecurity()->generatePasswordHash('plokijuh'),
                'role_id' => 1
            ]
        );
    }

    /**
     * {@inheritdoc}
     */
    public function safeDown()
    {
        echo "m220531_011059_seed_user_table cannot be reverted.\n";

        return false;
    }

    /*
    // Use up()/down() to run migration code without a transaction.
    public function up()
    {

    }

    public function down()
    {
        echo "m220531_011059_seed_user_table cannot be reverted.\n";

        return false;
    }
    */
}
