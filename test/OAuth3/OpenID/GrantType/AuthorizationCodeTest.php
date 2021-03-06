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


namespace OAuth3\OpenID\GrantType;

use OAuth3\Storage\Bootstrap;
use OAuth3\Server;
use OAuth3\Request\TestRequest;
use OAuth3\Response;
use PHPUnit\Framework\TestCase;

class AuthorizationCodeTest extends TestCase
{
    public function testValidCode()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-openid', // valid code
        ));
        $token = $server->grantAccessToken($request, new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('id_token', $token);
        $this->assertEquals('test_id_token', $token['id_token']);

        // this is only true if "offline_access" was requested
        $this->assertFalse(isset($token['refresh_token']));
    }

    public function testOfflineAccess()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-openid', // valid code
            'scope'         => 'offline_access', // valid code
        ));
        $token = $server->grantAccessToken($request, new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('id_token', $token);
        $this->assertEquals('test_id_token', $token['id_token']);
        $this->assertTrue(isset($token['refresh_token']));
    }

    private function getTestServer()
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage, array('use_openid_connect' => true));
        $server->addGrantType(new AuthorizationCode($storage));

        return $server;
    }
}
