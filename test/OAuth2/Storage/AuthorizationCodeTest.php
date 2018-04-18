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

class AuthorizationCodeTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testGetAuthorizationCode(AuthorizationCodeInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // nonexistant client_id
        $details = $storage->getAuthorizationCode('faketoken');
        $this->assertFalse($details);

        // valid client_id
        $details = $storage->getAuthorizationCode('testtoken');
        $this->assertNotNull($details);
    }

    /** @dataProvider provideStorage */
    public function testSetAuthorizationCode(AuthorizationCodeInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // assert code we are about to add does not exist
        $code = $storage->getAuthorizationCode('newcode');
        $this->assertFalse($code);

        // add new code
        $expires = time() + 20;
        $success = $storage->setAuthorizationCode('newcode', 'client ID', 'SOMEUSERID', 'http://example.com', $expires);
        $this->assertTrue($success);

        $code = $storage->getAuthorizationCode('newcode');
        $this->assertNotNull($code);
        $this->assertArrayHasKey('authorization_code', $code);
        $this->assertArrayHasKey('client_id', $code);
        $this->assertArrayHasKey('user_id', $code);
        $this->assertArrayHasKey('redirect_uri', $code);
        $this->assertArrayHasKey('expires', $code);
        $this->assertEquals($code['authorization_code'], 'newcode');
        $this->assertEquals($code['client_id'], 'client ID');
        $this->assertEquals($code['user_id'], 'SOMEUSERID');
        $this->assertEquals($code['redirect_uri'], 'http://example.com');
        $this->assertEquals($code['expires'], $expires);

        // change existing code
        $expires = time() + 42;
        $success = $storage->setAuthorizationCode('newcode', 'client ID2', 'SOMEOTHERID', 'http://example.org', $expires);
        $this->assertTrue($success);

        $code = $storage->getAuthorizationCode('newcode');
        $this->assertNotNull($code);
        $this->assertArrayHasKey('authorization_code', $code);
        $this->assertArrayHasKey('client_id', $code);
        $this->assertArrayHasKey('user_id', $code);
        $this->assertArrayHasKey('redirect_uri', $code);
        $this->assertArrayHasKey('expires', $code);
        $this->assertEquals($code['authorization_code'], 'newcode');
        $this->assertEquals($code['client_id'], 'client ID2');
        $this->assertEquals($code['user_id'], 'SOMEOTHERID');
        $this->assertEquals($code['redirect_uri'], 'http://example.org');
        $this->assertEquals($code['expires'], $expires);

        // add new code with scope having an empty string value
        $expires = time() + 20;
        $success = $storage->setAuthorizationCode('newcode', 'client ID', 'SOMEUSERID', 'http://example.com', $expires, '');
        $this->assertTrue($success);
    }

        /** @dataProvider provideStorage */
    public function testExpireAccessToken(AccessTokenInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // create a valid code
        $expires = time() + 20;
        $success = $storage->setAuthorizationCode('code-to-expire', 'client ID', 'SOMEUSERID', 'http://example.com', time() + 20);
        $this->assertTrue($success);

        // verify the new code exists
        $code = $storage->getAuthorizationCode('code-to-expire');
        $this->assertNotNull($code);

        $this->assertArrayHasKey('authorization_code', $code);
        $this->assertEquals($code['authorization_code'], 'code-to-expire');

        // now expire the code and ensure it's no longer available
        $storage->expireAuthorizationCode('code-to-expire');
        $code = $storage->getAuthorizationCode('code-to-expire');
        $this->assertFalse($code);
    }
}
