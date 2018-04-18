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


namespace OAuth3\ResponseType;

use OAuth3\Server;
use OAuth3\Storage\Memory;
use PHPUnit\Framework\TestCase;

class AccessTokenTest extends TestCase
{
    public function testRevokeAccessTokenWithTypeHint()
    {
        $tokenStorage = new Memory(array(
            'access_tokens' => array(
                'revoke' => array('mytoken'),
            ),
        ));

        $this->assertEquals(array('mytoken'), $tokenStorage->getAccessToken('revoke'));
        $accessToken = new AccessToken($tokenStorage);
        $accessToken->revokeToken('revoke', 'access_token');
        $this->assertFalse($tokenStorage->getAccessToken('revoke'));
    }

    public function testRevokeAccessTokenWithoutTypeHint()
    {
        $tokenStorage = new Memory(array(
            'access_tokens' => array(
                'revoke' => array('mytoken'),
            ),
        ));

        $this->assertEquals(array('mytoken'), $tokenStorage->getAccessToken('revoke'));
        $accessToken = new AccessToken($tokenStorage);
        $accessToken->revokeToken('revoke');
        $this->assertFalse($tokenStorage->getAccessToken('revoke'));
    }

    public function testRevokeRefreshTokenWithTypeHint()
    {
        $tokenStorage = new Memory(array(
            'refresh_tokens' => array(
                'revoke' => array('mytoken'),
            ),
        ));

        $this->assertEquals(array('mytoken'), $tokenStorage->getRefreshToken('revoke'));
        $accessToken = new AccessToken(new Memory, $tokenStorage);
        $accessToken->revokeToken('revoke', 'refresh_token');
        $this->assertFalse($tokenStorage->getRefreshToken('revoke'));
    }

    public function testRevokeRefreshTokenWithoutTypeHint()
    {
        $tokenStorage = new Memory(array(
            'refresh_tokens' => array(
                'revoke' => array('mytoken'),
            ),
        ));

        $this->assertEquals(array('mytoken'), $tokenStorage->getRefreshToken('revoke'));
        $accessToken = new AccessToken(new Memory, $tokenStorage);
        $accessToken->revokeToken('revoke');
        $this->assertFalse($tokenStorage->getRefreshToken('revoke'));
    }

    public function testRevokeAccessTokenWithRefreshTokenTypeHint()
    {
        $tokenStorage = new Memory(array(
            'access_tokens' => array(
                'revoke' => array('mytoken'),
            ),
        ));

        $this->assertEquals(array('mytoken'), $tokenStorage->getAccessToken('revoke'));
        $accessToken = new AccessToken($tokenStorage);
        $accessToken->revokeToken('revoke', 'refresh_token');
        $this->assertFalse($tokenStorage->getAccessToken('revoke'));
    }

    public function testRevokeAccessTokenWithBogusTypeHint()
    {
        $tokenStorage = new Memory(array(
            'access_tokens' => array(
                'revoke' => array('mytoken'),
            ),
        ));

        $this->assertEquals(array('mytoken'), $tokenStorage->getAccessToken('revoke'));
        $accessToken = new AccessToken($tokenStorage);
        $accessToken->revokeToken('revoke', 'foo');
        $this->assertFalse($tokenStorage->getAccessToken('revoke'));
    }

    public function testRevokeRefreshTokenWithBogusTypeHint()
    {
        $tokenStorage = new Memory(array(
            'refresh_tokens' => array(
                'revoke' => array('mytoken'),
            ),
        ));

        $this->assertEquals(array('mytoken'), $tokenStorage->getRefreshToken('revoke'));
        $accessToken = new AccessToken(new Memory, $tokenStorage);
        $accessToken->revokeToken('revoke', 'foo');
        $this->assertFalse($tokenStorage->getRefreshToken('revoke'));
    }
}
