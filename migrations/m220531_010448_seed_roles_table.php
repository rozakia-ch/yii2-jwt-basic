<?php

use yii\db\Migration;

/**
 * Class m220531_010448_seed_roles_table
 */
class m220531_010448_seed_roles_table extends Migration
{
    /**
     * {@inheritdoc}
     */
    public function safeUp()
    {
        $this->insert(
            'roles',
            [
                'role_name' => 'admin',
            ]
        );
    }

    /**
     * {@inheritdoc}
     */
    public function safeDown()
    {
        echo "m220531_010448_seed_roles_table cannot be reverted.\n";

        return false;
    }

    /*
    // Use up()/down() to run migration code without a transaction.
    public function up()
    {

    }

    public function down()
    {
        echo "m220531_010448_seed_roles_table cannot be reverted.\n";

        return false;
    }
    */
}
