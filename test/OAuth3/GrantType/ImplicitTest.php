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


namespace OAuth3\GrantType;

use OAuth3\Storage\Bootstrap;
use OAuth3\Server;
use OAuth3\Request;
use OAuth3\Response;
use PHPUnit\Framework\TestCase;

class ImplicitTest extends TestCase
{
    public function testImplicitNotAllowedResponse()
    {
        $server = $this->getTestServer();
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'token', // invalid response type
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), false);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'unsupported_response_type');
        $this->assertEquals($query['error_description'], 'implicit grant type not supported');
    }

    public function testUserDeniesAccessResponse()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'token', // valid response type
            'state' => 'xyz',
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), false);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'access_denied');
        $this->assertEquals($query['error_description'], 'The user denied access to your application');
    }

    public function testSuccessfulRequestFragmentParameter()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'token', // valid response type
            'state' => 'xyz',
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);

        $this->assertEquals('http', $parts['scheme']); // same as passed in to redirect_uri
        $this->assertEquals('adobe.com', $parts['host']); // same as passed in to redirect_uri
        $this->assertArrayHasKey('fragment', $parts);
        $this->assertFalse(isset($parts['query']));

        // assert fragment is in "application/x-www-form-urlencoded" format
        parse_str($parts['fragment'], $params);
        $this->assertNotNull($params);
        $this->assertArrayHasKey('access_token', $params);
        $this->assertArrayHasKey('expires_in', $params);
        $this->assertArrayHasKey('token_type', $params);
    }

    public function testSuccessfulRequestReturnsStateParameter()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'token', // valid response type
            'state' => 'test', // valid state string (just needs to be passed back to us)
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        $this->assertArrayHasKey('fragment', $parts);
        parse_str($parts['fragment'], $params);

        $this->assertArrayHasKey('state', $params);
        $this->assertEquals($params['state'], 'test');
    }

    public function testSuccessfulRequestStripsExtraParameters()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com?fake=something', // valid redirect URI
            'response_type' => 'token', // valid response type
            'state' => 'test', // valid state string (just needs to be passed back to us)
            'fake' => 'something', // add extra param to querystring
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        $this->assertFalse(isset($parts['fake']));
        $this->assertArrayHasKey('fragment', $parts);
        parse_str($parts['fragment'], $params);

        $this->assertFalse(isset($params['fake']));
        $this->assertArrayHasKey('state', $params);
        $this->assertEquals($params['state'], 'test');
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
