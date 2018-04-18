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

class RefreshTokenTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testSetRefreshToken(RefreshTokenInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // assert token we are about to add does not exist
        $token = $storage->getRefreshToken('refreshtoken');
        $this->assertFalse($token);

        // add new token
        $expires = time() + 20;
        $success = $storage->setRefreshToken('refreshtoken', 'client ID', 'SOMEUSERID', $expires);
        $this->assertTrue($success);

        $token = $storage->getRefreshToken('refreshtoken');
        $this->assertNotNull($token);
        $this->assertArrayHasKey('refresh_token', $token);
        $this->assertArrayHasKey('client_id', $token);
        $this->assertArrayHasKey('user_id', $token);
        $this->assertArrayHasKey('expires', $token);
        $this->assertEquals($token['refresh_token'], 'refreshtoken');
        $this->assertEquals($token['client_id'], 'client ID');
        $this->assertEquals($token['user_id'], 'SOMEUSERID');
        $this->assertEquals($token['expires'], $expires);

        // add token with scope having an empty string value
        $expires = time() + 20;
        $success = $storage->setRefreshToken('refreshtoken2', 'client ID', 'SOMEUSERID', $expires, '');
        $this->assertTrue($success);
    }
}
