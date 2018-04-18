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


namespace OAuth3\OpenID\Controller;

use OAuth3\Storage\Bootstrap;
use OAuth3\Server;
use OAuth3\Request;
use OAuth3\Response;
use PHPUnit\Framework\TestCase;

class UserInfoControllerTest extends TestCase
{
    public function testCreateController()
    {
        $tokenType = new \OAuth3\TokenType\Bearer();
        $storage = new \OAuth3\Storage\Memory();
        $controller = new UserInfoController($tokenType, $storage, $storage);

        $response = new Response();
        $controller->handleUserInfoRequest(new Request(), $response);
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testValidToken()
    {
        $server = $this->getTestServer();
        $request = Request::createFromGlobals();
        $request->headers['AUTHORIZATION'] = 'Bearer accesstoken-openid-connect';
        $response = new Response();

        $server->handleUserInfoRequest($request, $response);
        $parameters = $response->getParameters();
        $this->assertEquals($parameters['sub'], 'testuser');
        $this->assertEquals($parameters['email'], 'testuser@test.com');
        $this->assertEquals($parameters['email_verified'], true);
    }

    private function getTestServer($config = array())
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage, $config);

        return $server;
    }
}
