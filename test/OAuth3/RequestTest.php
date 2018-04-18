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


namespace OAuth3;

use OAuth3\Request\TestRequest;
use OAuth3\Storage\Bootstrap;
use OAuth3\GrantType\AuthorizationCode;
use PHPUnit\Framework\TestCase;

class RequestTest extends TestCase
{
    public function testRequestOverride()
    {
        $request = new TestRequest();
        $server = $this->getTestServer();

        // Smoke test for override request class
        // $server->handleTokenRequest($request, $response = new Response());
        // $this->assertInstanceOf('Response', $response);
        // $server->handleAuthorizeRequest($request, $response = new Response(), true);
        // $this->assertInstanceOf('Response', $response);
        // $response = $server->verifyResourceRequest($request, $response = new Response());
        // $this->assertTrue(is_bool($response));

        /*** make some valid requests ***/

        // Valid Token Request
        $request->setPost(array(
            'grant_type' => 'authorization_code',
            'client_id'  => 'Test Client ID',
            'client_secret' => 'TestSecret',
            'code' => 'testcode',
        ));
        $server->handleTokenRequest($request, $response = new Response());
        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNull($response->getParameter('error'));
        $this->assertNotNUll($response->getParameter('access_token'));
    }

    public function testHeadersReturnsValueByKey()
    {
        $request = new Request(
            array(),
            array(),
            array(),
            array(),
            array(),
            array(),
            array(),
            array('AUTHORIZATION' => 'Basic secret')
        );

        $this->assertEquals('Basic secret', $request->headers('AUTHORIZATION'));
    }

    public function testHeadersReturnsDefaultIfHeaderNotPresent()
    {
        $request = new Request();

        $this->assertEquals('Bearer', $request->headers('AUTHORIZATION', 'Bearer'));
    }

    public function testHeadersIsCaseInsensitive()
    {
        $request = new Request(
            array(),
            array(),
            array(),
            array(),
            array(),
            array(),
            array(),
            array('AUTHORIZATION' => 'Basic secret')
        );

        $this->assertEquals('Basic secret', $request->headers('Authorization'));
    }

    public function testRequestReturnsPostParamIfNoQueryParamAvailable()
    {
        $request = new Request(
            array(),
            array('client_id' => 'correct')
        );

        $this->assertEquals('correct', $request->query('client_id', $request->request('client_id')));
    }

    public function testRequestHasHeadersAndServerHeaders()
    {
        $request = new Request(
            array(),
            array(),
            array(),
            array(),
            array(),
            array('CONTENT_TYPE' => 'text/xml', 'PHP_AUTH_USER' => 'client_id', 'PHP_AUTH_PW' => 'client_pass'),
            null,
            array('CONTENT_TYPE' => 'application/json')
        );

        $this->assertSame('client_id', $request->headers('PHP_AUTH_USER'));
        $this->assertSame('client_pass', $request->headers('PHP_AUTH_PW'));
        $this->assertSame('application/json', $request->headers('CONTENT_TYPE'));
    }

    private function getTestServer($config = array())
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage, $config);

        // Add the two types supported for authorization grant
        $server->addGrantType(new AuthorizationCode($storage));

        return $server;
    }
}
