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


namespace OAuth3\Controller;

use OAuth3\Storage\Bootstrap;
use OAuth3\Server;
use OAuth3\GrantType\AuthorizationCode;
use OAuth3\GrantType\ClientCredentials;
use OAuth3\GrantType\UserCredentials;
use OAuth3\Scope;
use OAuth3\Request\TestRequest;
use OAuth3\Response;
use PHPUnit\Framework\TestCase;

class TokenControllerTest extends TestCase
{
    public function testNoGrantType()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $server->handleTokenRequest(TestRequest::createPost(), $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'The grant type was not specified in the request');
    }

    public function testInvalidGrantType()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'invalid_grant_type', // invalid grant type
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'unsupported_grant_type');
        $this->assertEquals($response->getParameter('error_description'), 'Grant type "invalid_grant_type" not supported');
    }

    public function testNoClientId()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'Client credentials were not found in the headers or body');
    }

    public function testNoClientSecretWithConfidentialClient()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
            'client_id' => 'Test Client ID', // valid client id
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'This client is invalid or must authenticate using a client secret');
    }

    public function testNoClientSecretWithEmptySecret()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode-empty-secret',
            'client_id' => 'Test Client ID Empty Secret', // valid client id
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 200);
    }

    public function testInvalidClientId()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
            'client_id'  => 'Fake Client ID', // invalid client id
            'client_secret' => 'TestSecret', // valid client secret
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'The client credentials are invalid');
    }

    public function testInvalidClientSecret()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
            'client_id'  => 'Test Client ID', // valid client id
            'client_secret' => 'Fake Client Secret', // invalid client secret
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'The client credentials are invalid');
    }

    public function testValidTokenResponse()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code' => 'testcode', // valid authorization code
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertTrue($response instanceof Response);
        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));
        $this->assertNotNull($response->getParameter('access_token'));
        $this->assertNotNull($response->getParameter('expires_in'));
        $this->assertNotNull($response->getParameter('token_type'));
    }

    public function testValidClientIdScope()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'scope' => 'clientscope1 clientscope2'
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));
        $this->assertEquals('clientscope1 clientscope2', $response->getParameter('scope'));
    }

    public function testInvalidClientIdScope()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode-with-scope',
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'scope' => 'clientscope3'
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_scope');
        $this->assertEquals($response->getParameter('error_description'), 'The scope requested is invalid for this request');
    }

    public function testEnforceScope()
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage);
        $server->addGrantType(new ClientCredentials($storage));

        $scope = new Scope(array(
            'default_scope' => false,
            'supported_scopes' => array('testscope')
        ));
        $server->setScopeUtil($scope);

        $request = TestRequest::createPost(array(
            'grant_type' => 'client_credentials', // valid grant type
            'client_id'  => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
        ));
        $response = $server->handleTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_scope');
        $this->assertEquals($response->getParameter('error_description'), 'This application requires you specify a scope parameter');
    }

    public function testCanReceiveAccessTokenUsingPasswordGrantTypeWithoutClientSecret()
    {
        // add the test parameters in memory
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage);
        $server->addGrantType(new UserCredentials($storage));

        $request = TestRequest::createPost(array(
            'grant_type' => 'password',                          // valid grant type
            'client_id'  => 'Test Client ID For Password Grant', // valid client id
            'username'   => 'johndoe',                           // valid username
            'password'   => 'password',                          // valid password for username
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertTrue($response instanceof Response);
        $this->assertEquals(200, $response->getStatusCode(), var_export($response, 1));
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));
        $this->assertNotNull($response->getParameter('access_token'));
        $this->assertNotNull($response->getParameter('expires_in'));
        $this->assertNotNull($response->getParameter('token_type'));
    }

    public function testInvalidTokenTypeHintForRevoke()
    {
        $server = $this->getTestServer();

        $request = TestRequest::createPost(array(
            'token_type_hint' => 'foo',
            'token' => 'sometoken'
        ));

        $server->handleRevokeRequest($request, $response = new Response());

        $this->assertTrue($response instanceof Response);
        $this->assertEquals(400, $response->getStatusCode(), var_export($response, 1));
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Token type hint must be either \'access_token\' or \'refresh_token\'');
    }

    public function testMissingTokenForRevoke()
    {
        $server = $this->getTestServer();

        $request = TestRequest::createPost(array(
            'token_type_hint' => 'access_token'
        ));

        $server->handleRevokeRequest($request, $response = new Response());
        $this->assertTrue($response instanceof Response);
        $this->assertEquals(400, $response->getStatusCode(), var_export($response, 1));
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing token parameter to revoke');
    }

    public function testInvalidRequestMethodForRevoke()
    {
        $server = $this->getTestServer();

        $request = new TestRequest();
        $request->setQuery(array(
            'token_type_hint' => 'access_token'
        ));

        $server->handleRevokeRequest($request, $response = new Response());
        $this->assertTrue($response instanceof Response);
        $this->assertEquals(405, $response->getStatusCode(), var_export($response, 1));
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'The request method must be POST when revoking an access token');
    }

    public function testCanUseCrossOriginRequestForRevoke()
    {
        $server = $this->getTestServer();

        $request = new TestRequest();
        $request->setMethod('OPTIONS');

        $server->handleRevokeRequest($request, $response = new Response());
        $this->assertTrue($response instanceof Response);
        $this->assertEquals(200, $response->getStatusCode(), var_export($response, 1));
        $this->assertEquals($response->getHttpHeader('Allow'), 'POST, OPTIONS');
    }

    public function testInvalidRequestMethodForAccessToken()
    {
        $server = $this->getTestServer();

        $request = new TestRequest();
        $request->setQuery(array(
            'token_type_hint' => 'access_token'
        ));

        $server->handleTokenRequest($request, $response = new Response());
        $this->assertTrue($response instanceof Response);
        $this->assertEquals(405, $response->getStatusCode(), var_export($response, 1));
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'The request method must be POST when requesting an access token');
    }

    public function testCanUseCrossOriginRequestForAccessToken()
    {
        $server = $this->getTestServer();

        $request = new TestRequest();
        $request->setMethod('OPTIONS');

        $server->handleTokenRequest($request, $response = new Response());
        $this->assertTrue($response instanceof Response);
        $this->assertEquals(200, $response->getStatusCode(), var_export($response, 1));
        $this->assertEquals($response->getHttpHeader('Allow'), 'POST, OPTIONS');
    }

    public function testCreateController()
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $accessToken = new \OAuth3\ResponseType\AccessToken($storage);
        $controller = new TokenController($accessToken, $storage);
    }

    private function getTestServer()
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage);
        $server->addGrantType(new AuthorizationCode($storage));

        return $server;
    }
}
