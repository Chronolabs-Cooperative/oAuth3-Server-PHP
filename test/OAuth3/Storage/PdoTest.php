<?php
/**
 * oAuth 3.0 Self Discovery Server API ~ Services
 *
 * You may not change or alter any portion of this comment or credits
 * of supporting developers from this source code or any supporting source code
 * which is considered copyrighted (c) material of the original comment or credit authors.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * @copyright       Chronolabs Cooperative http://syd.au.snails.email
 * @license         ACADEMIC APL 2 (https://sourceforge.net/u/chronolabscoop/wiki/Academic%20Public%20License%2C%20version%202.0/)
 * @license         GNU GPL 3 (http://www.gnu.org/licenses/gpl.html)
 * @package         oauth3
 * @since           3.0.0
 * @author          Brent Shaffer <bshafs@gmail.com>
 * @author          Dr. Simon Antony Roberts <simon@snails.email>
 * @version         3.0.7
 * @description		A standards compliant implementation of an OAuth 3.0 authorization server written in PHP
 * @link            http://internetfounder.wordpress.com
 * @link            https://github.com/Chronolabs-Cooperative/oAuth3-Server-PHP
 * @link            https://sourceforge.net/p/chronolabs-cooperative/oAuth3-Server-PHP
 * @link            https://facebook.com/ChronolabsCoop
 * @link            https://twitter.com/ChronolabsCoop
 * @see             https://github.com/thephpleague/oauth2-server
 *
 */

namespace OAuth3\Storage;

class PdoTest extends BaseTest
{
    public function testCreatePdoStorageUsingPdoClass()
    {
        $dsn = sprintf('sqlite:%s', Bootstrap::getInstance()->getSqliteDir());
        $pdo = new \PDO($dsn);
        $storage = new Pdo($pdo);

        $this->assertNotNull($storage->getClientDetails('oauth_test_client'));
    }

    public function testCreatePdoStorageUsingDSN()
    {
        $dsn = sprintf('sqlite:%s', Bootstrap::getInstance()->getSqliteDir());
        $storage = new Pdo($dsn);

        $this->assertNotNull($storage->getClientDetails('oauth_test_client'));
    }

    public function testCreatePdoStorageUsingConfig()
    {
        $dsn = sprintf('sqlite:%s', Bootstrap::getInstance()->getSqliteDir());
        $config = array('dsn' => $dsn);
        $storage = new Pdo($config);

        $this->assertNotNull($storage->getClientDetails('oauth_test_client'));
    }

    /**
     * @expectedException InvalidArgumentException dsn
     */
    public function testCreatePdoStorageWithoutDSNThrowsException()
    {
        $config = array('username' => 'brent', 'password' => 'brentisaballer');
        $storage = new Pdo($config);
    }
}
