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

use OAuth3\Scope;

class ScopeTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testScopeExists($storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        if (!$storage instanceof ScopeInterface) {
            // incompatible storage
            return;
        }

        //Test getting scopes
        $scopeUtil = new Scope($storage);
        $this->assertTrue($scopeUtil->scopeExists('supportedscope1'));
        $this->assertTrue($scopeUtil->scopeExists('supportedscope1 supportedscope2 supportedscope3'));
        $this->assertFalse($scopeUtil->scopeExists('fakescope'));
        $this->assertFalse($scopeUtil->scopeExists('supportedscope1 supportedscope2 supportedscope3 fakescope'));
    }

    /** @dataProvider provideStorage */
    public function testGetDefaultScope($storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        if (!$storage instanceof ScopeInterface) {
            // incompatible storage
            return;
        }

        // test getting default scope
        $scopeUtil = new Scope($storage);
        $expected = explode(' ', $scopeUtil->getDefaultScope());
        $actual = explode(' ', 'defaultscope1 defaultscope2');
        sort($expected);
        sort($actual);
        $this->assertEquals($expected, $actual);
    }
}
