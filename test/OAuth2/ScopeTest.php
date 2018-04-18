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


namespace OAuth2;

use OAuth2\Storage\Memory;
use PHPUnit\Framework\TestCase;

class ScopeTest extends TestCase
{
    public function testCheckScope()
    {
        $scopeUtil = new Scope();

        $this->assertFalse($scopeUtil->checkScope('invalid', 'list of scopes'));
        $this->assertTrue($scopeUtil->checkScope('valid', 'valid and-some other-scopes'));
        $this->assertTrue($scopeUtil->checkScope('valid another-valid', 'valid another-valid and-some other-scopes'));
        // all scopes must match
        $this->assertFalse($scopeUtil->checkScope('valid invalid', 'valid and-some other-scopes'));
        $this->assertFalse($scopeUtil->checkScope('valid valid2 invalid', 'valid valid2 and-some other-scopes'));
    }

    public function testScopeStorage()
    {
        $scopeUtil = new Scope();
        $this->assertEquals($scopeUtil->getDefaultScope(), null);

        $scopeUtil = new Scope(array(
            'default_scope' => 'default',
            'supported_scopes' => array('this', 'that', 'another'),
        ));
        $this->assertEquals($scopeUtil->getDefaultScope(), 'default');
        $this->assertTrue($scopeUtil->scopeExists('this that another', 'client_id'));

        $memoryStorage = new Memory(array(
            'default_scope' => 'base',
            'supported_scopes' => array('only-this-one'),
        ));
        $scopeUtil = new Scope($memoryStorage);

        $this->assertEquals($scopeUtil->getDefaultScope(), 'base');
        $this->assertTrue($scopeUtil->scopeExists('only-this-one', 'client_id'));
    }
}
