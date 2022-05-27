<?php

use yii\db\Migration;

/**
 * Handles the creation of table `{{%user_refresh_tokens}}`.
 */
class m220527_060826_create_user_refresh_tokens_table extends Migration
{
    /**
     * {@inheritdoc}
     */
    public function safeUp()
    {
        $this->createTable('{{%user_refresh_tokens}}', [
            'user_refresh_tokenID' => $this->primaryKey(),
            'urf_userID' => $this->integer()->unsigned()->notNull(),
            'urf_token' => $this->string(1000)->notNull(),
            'urf_ip' => $this->string(50)->notNull(),
            'urf_user_agent' => $this->string(1000)->notNull(),
            'urf_created' => $this->datetime()->notNull(),
        ]);
        // creates index for column `urf_userID`
        $this->createIndex(
            '{{%idx-user_refresh_tokens-urf_userID}}',
            '{{%user_refresh_tokens}}',
            'urf_userID'
        );

        // add foreign key for table `{{%user}}`
        $this->addForeignKey(
            '{{%fk-user_refresh_tokens-urf_userID}}',
            '{{%user_refresh_tokens}}',
            'urf_userID',
            '{{%users}}',
            'id',
            'CASCADE'
        );
    }

    /**
     * {@inheritdoc}
     */
    public function safeDown()
    {
        /// drops foreign key for table `{{%user}}`
        $this->dropForeignKey(
            '{{%fk-user_refresh_tokens-urf_userID}}',
            '{{%user_refresh_tokens}}'
        );

        // drops index for column `urf_userID`
        $this->dropIndex(
            '{{%idx-user_refresh_tokens-urf_userID}}',
            '{{%user_refresh_tokens}}'
        );

        $this->dropTable('{{%user_refresh_tokens}}');
    }
}
