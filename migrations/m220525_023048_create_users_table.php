<?php

use yii\db\Migration;

/**
 * Handles the creation of table `{{%users}}`.
 */
class m220525_023048_create_users_table extends Migration
{
    /**
     * {@inheritdoc}
     */
    public function safeUp()
    {
        $this->createTable('{{%users}}', [
            'id' => $this->primaryKey()->unsigned(),
            'name' => $this->string()->notNull(),
            'username' => $this->string()->notNull()->unique(),
            'email' => $this->string()->notNull()->unique(),
            'password' => $this->string()->notNull(),
            'role_id' => $this->integer()->notNull(),
            'auth_key' => $this->string(),
            'created_at' => $this->timestamp()->defaultExpression('NOW()'),
            'updated_at' => $this->timestamp()->defaultExpression('CURRENT_TIMESTAMP')->append('ON UPDATE NOW()'),
        ]);
        // creates index for column `user_id`
        $this->createIndex(
            '{{%idx-users-role_id}}',
            '{{%users}}',
            'role_id'
        );

        // add foreign key for table `{{%user}}`
        $this->addForeignKey(
            '{{%fk-users-role_id}}',
            '{{%users}}',
            'role_id',
            '{{%roles}}',
            'id',
            'CASCADE'
        );
    }

    /**
     * {@inheritdoc}
     */
    public function safeDown()
    {
        // drops foreign key for table `{{%user}}`
        $this->dropForeignKey(
            '{{%fk-users-role_id}}',
            '{{%users}}'
        );

        // drops index for column `role_id`
        $this->dropIndex(
            '{{%idx-users-role_id}}',
            '{{%users}}'
        );

        $this->dropTable('{{%users}}');
    }
}
