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


namespace OAuth2\Storage;

class AccessTokenTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testSetAccessToken(AccessTokenInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // assert token we are about to add does not exist
        $token = $storage->getAccessToken('newtoken');
        $this->assertFalse($token);

        // add new token
        $expires = time() + 20;
        $success = $storage->setAccessToken('newtoken', 'client ID', 'SOMEUSERID', $expires);
        $this->assertTrue($success);

        $token = $storage->getAccessToken('newtoken');
        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('client_id', $token);
        $this->assertArrayHasKey('user_id', $token);
        $this->assertArrayHasKey('expires', $token);
        $this->assertEquals($token['access_token'], 'newtoken');
        $this->assertEquals($token['client_id'], 'client ID');
        $this->assertEquals($token['user_id'], 'SOMEUSERID');
        $this->assertEquals($token['expires'], $expires);

        // change existing token
        $expires = time() + 42;
        $success = $storage->setAccessToken('newtoken', 'client ID2', 'SOMEOTHERID', $expires);
        $this->assertTrue($success);

        $token = $storage->getAccessToken('newtoken');
        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('client_id', $token);
        $this->assertArrayHasKey('user_id', $token);
        $this->assertArrayHasKey('expires', $token);
        $this->assertEquals($token['access_token'], 'newtoken');
        $this->assertEquals($token['client_id'], 'client ID2');
        $this->assertEquals($token['user_id'], 'SOMEOTHERID');
        $this->assertEquals($token['expires'], $expires);

        // add token with scope having an empty string value
        $expires = time() + 42;
        $success = $storage->setAccessToken('newtoken', 'client ID', 'SOMEOTHERID', $expires, '');
        $this->assertTrue($success);
    }

    /** @dataProvider provideStorage */
    public function testUnsetAccessToken(AccessTokenInterface $storage)
    {
        if ($storage instanceof NullStorage || !method_exists($storage, 'unsetAccessToken')) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // assert token we are about to unset does not exist
        $token = $storage->getAccessToken('revokabletoken');
        $this->assertFalse($token);

        // add new token
        $expires = time() + 20;
        $success = $storage->setAccessToken('revokabletoken', 'client ID', 'SOMEUSERID', $expires);
        $this->assertTrue($success);

        // assert unsetAccessToken returns true
        $result = $storage->unsetAccessToken('revokabletoken');
        $this->assertTrue($result);

        // assert token we unset does not exist
        $token = $storage->getAccessToken('revokabletoken');
        $this->assertFalse($token);
    }

    /** @dataProvider provideStorage */
    public function testUnsetAccessTokenReturnsFalse(AccessTokenInterface $storage)
    {
        if ($storage instanceof NullStorage || !method_exists($storage, 'unsetAccessToken')) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // assert token we are about to unset does not exist
        $token = $storage->getAccessToken('nonexistanttoken');
        $this->assertFalse($token);

        // assert unsetAccessToken returns false
        $result = $storage->unsetAccessToken('nonexistanttoken');
        $this->assertFalse($result);
    }
}
