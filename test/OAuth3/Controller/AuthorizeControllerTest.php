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

use OAuth3\Storage\Memory;
use OAuth3\Scope;
use OAuth3\Storage\Bootstrap;
use OAuth3\Server;
use OAuth3\GrantType\AuthorizationCode;
use OAuth3\Request;
use OAuth3\Response;
use OAuth3\Request\TestRequest;
use PHPUnit\Framework\TestCase;

class AuthorizeControllerTest extends TestCase
{
    public function testNoClientIdResponse()
    {
        $server = $this->getTestServer();
        $request = new Request();
        $server->handleAuthorizeRequest($request, $response = new Response(), false);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'No client id supplied');
    }

    public function testInvalidClientIdResponse()
    {
        $server = $this->getTestServer();
        $request = new Request(array(
            'client_id' => 'Fake Client ID', // invalid client id
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), false);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'The client id supplied is invalid');
    }

    public function testNoRedirectUriSuppliedOrStoredResponse()
    {
        $server = $this->getTestServer();
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), false);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_uri');
        $this->assertEquals($response->getParameter('error_description'), 'No redirect URI was supplied or stored');
    }

    public function testNoResponseTypeResponse()
    {
        $server = $this->getTestServer();
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), false);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_request');
        $this->assertEquals($query['error_description'], 'Invalid or missing response type');
    }

    public function testInvalidResponseTypeResponse()
    {
        $server = $this->getTestServer();
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'invalid', // invalid response type
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), false);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_request');
        $this->assertEquals($query['error_description'], 'Invalid or missing response type');
    }

    public function testRedirectUriFragmentResponse()
    {
        $server = $this->getTestServer();
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com#fragment', // valid redirect URI
            'response_type' => 'code', // invalid response type
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_uri');
        $this->assertEquals($response->getParameter('error_description'), 'The redirect URI must not contain a fragment');
    }

    public function testEnforceState()
    {
        $server = $this->getTestServer(array('enforce_state' => true));
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_request');
        $this->assertEquals($query['error_description'], 'The state parameter is required');
    }

    public function testDoNotEnforceState()
    {
        $server = $this->getTestServer(array('enforce_state' => false));
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertNotContains('error', $response->getHttpHeader('Location'));
    }

    public function testEnforceScope()
    {
        $server = $this->getTestServer();
        $scopeStorage = new Memory(array('default_scope' => false, 'supported_scopes' => array('testscope')));
        $server->setScopeUtil(new Scope($scopeStorage));

        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
            'state' => 'xyz',
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $parts = parse_url($response->getHttpHeader('Location'));
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_client');
        $this->assertEquals($query['error_description'], 'This application requires you specify a scope parameter');

        $request->query['scope'] = 'testscope';
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertNotContains('error', $response->getHttpHeader('Location'));
    }

    public function testInvalidRedirectUri()
    {
        $server = $this->getTestServer();
        $request = new Request(array(
            'client_id' => 'Test Client ID with Redirect Uri', // valid client id
            'redirect_uri' => 'http://adobe.com', // invalid redirect URI
            'response_type' => 'code',
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'redirect_uri_mismatch');
        $this->assertEquals($response->getParameter('error_description'), 'The redirect URI provided is missing or does not match');
    }

    public function testInvalidRedirectUriApprovedByBuggyRegisteredUri()
    {
        $server = $this->getTestServer();
        $server->setConfig('require_exact_redirect_uri', false);
        $request = new Request(array(
            'client_id' => 'Test Client ID with Buggy Redirect Uri', // valid client id
            'redirect_uri' => 'http://adobe.com', // invalid redirect URI
            'response_type' => 'code',
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'redirect_uri_mismatch');
        $this->assertEquals($response->getParameter('error_description'), 'The redirect URI provided is missing or does not match');
    }

    public function testNoRedirectUriWithMultipleRedirectUris()
    {
        $server = $this->getTestServer();

        // create a request with no "redirect_uri" in querystring
        $request = new Request(array(
            'client_id' => 'Test Client ID with Multiple Redirect Uris', // valid client id
            'response_type' => 'code',
        ));

        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_uri');
        $this->assertEquals($response->getParameter('error_description'), 'A redirect URI must be supplied when multiple redirect URIs are registered');
    }

    public function testRedirectUriWithValidRedirectUri()
    {
        $server = $this->getTestServer();

        // create a request with no "redirect_uri" in querystring
        $request = new Request(array(
            'client_id'     => 'Test Client ID with Redirect Uri Parts', // valid client id
            'response_type' => 'code',
            'redirect_uri'  => 'http://user:pass@brentertainment.com:2222/authorize/cb?auth_type=oauth&test=true',
            'state'         => 'xyz',
        ));

        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertContains('code', $response->getHttpHeader('Location'));
    }

    public function testRedirectUriWithDifferentQueryAndExactMatchRequired()
    {
        $server = $this->getTestServer(array('require_exact_redirect_uri' => true));

        // create a request with no "redirect_uri" in querystring
        $request = new Request(array(
            'client_id' => 'Test Client ID with Redirect Uri Parts', // valid client id
            'response_type' => 'code',
            'redirect_uri' => 'http://user:pass@brentertainment.com:2222/authorize/cb?auth_type=oauth&test=true&hereisa=querystring',
        ));

        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'redirect_uri_mismatch');
        $this->assertEquals($response->getParameter('error_description'), 'The redirect URI provided is missing or does not match');
    }

    public function testRedirectUriWithDifferentQueryAndExactMatchNotRequired()
    {
        $server = $this->getTestServer(array('require_exact_redirect_uri' => false));

        // create a request with no "redirect_uri" in querystring
        $request = new Request(array(
            'client_id'     => 'Test Client ID with Redirect Uri Parts', // valid client id
            'response_type' => 'code',
            'redirect_uri'  => 'http://user:pass@brentertainment.com:2222/authorize/cb?auth_type=oauth&test=true&hereisa=querystring',
            'state'         => 'xyz',
        ));

        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertContains('code', $response->getHttpHeader('Location'));
    }

    public function testMultipleRedirectUris()
    {
        $server = $this->getTestServer();
        $request = new Request(array(
            'client_id'     => 'Test Client ID with Multiple Redirect Uris', // valid client id
            'redirect_uri'  => 'http://brentertainment.com', // valid redirect URI
            'response_type' => 'code',
            'state'         => 'xyz'
        ));

        $server->handleAuthorizeRequest($request, $response = new Response(), true);
        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertContains('code', $response->getHttpHeader('Location'));

        // call again with different (but still valid) redirect URI
        $request->query['redirect_uri'] = 'http://morehazards.com';

        $server->handleAuthorizeRequest($request, $response = new Response(), true);
        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertContains('code', $response->getHttpHeader('Location'));
    }

    /**
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.3
     * @see https://github.com/bshaffer/OAuth3-server-php/issues/163
     */
    public function testNoRedirectUriSuppliedDoesNotRequireTokenRedirectUri()
    {
        $server = $this->getTestServer();
        $request = new Request(array(
            'client_id'     => 'Test Client ID with Redirect Uri', // valid client id
            'response_type' => 'code',
            'state'         => 'xyz',
        ));

        $server->handleAuthorizeRequest($request, $response = new Response(), true);
        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertContains('state', $response->getHttpHeader('Location'));
        $this->assertStringStartsWith('http://brentertainment.com?code=', $response->getHttpHeader('Location'));

        $parts = parse_url($response->getHttpHeader('Location'));
        parse_str($parts['query'], $query);

        // call token endpoint with no redirect_uri supplied
        $request = TestRequest::createPost(array(
            'client_id'     => 'Test Client ID with Redirect Uri', // valid client id
            'client_secret' => 'TestSecret2',
            'grant_type'    => 'authorization_code',
            'code'          => $query['code'],
        ));

        $server->handleTokenRequest($request, $response = new Response(), true);
        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNotNull($response->getParameter('access_token'));
    }

    public function testUserDeniesAccessResponse()
    {
        $server = $this->getTestServer();
        $request = new Request(array(
            'client_id' => 'Test Client ID', // valid client id
            'redirect_uri' => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
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

    public function testCodeQueryParamIsSet()
    {
        $server = $this->getTestServer();
        $request = new Request(array(
            'client_id'     => 'Test Client ID', // valid client id
            'redirect_uri'  => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
            'state'         => 'xyz',
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);

        $this->assertEquals('http', $parts['scheme']); // same as passed in to redirect_uri
        $this->assertEquals('adobe.com', $parts['host']); // same as passed in to redirect_uri
        $this->assertArrayHasKey('query', $parts);
        $this->assertFalse(isset($parts['fragment']));

        // assert fragment is in "application/x-www-form-urlencoded" format
        parse_str($parts['query'], $query);
        $this->assertNotNull($query);
        $this->assertArrayHasKey('code', $query);

        // ensure no id_token was saved, since the openid scope wasn't requested
        $storage = $server->getStorage('authorization_code');
        $code = $storage->getAuthorizationCode($query['code']);
        $this->assertTrue(empty($code['id_token']));

        // ensure no error was returned
        $this->assertFalse(isset($query['error']));
        $this->assertFalse(isset($query['error_description']));
    }

    public function testSuccessfulRequestReturnsStateParameter()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = new Request(array(
            'client_id'     => 'Test Client ID', // valid client id
            'redirect_uri'  => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
            'state'         => 'test', // valid state string (just needs to be passed back to us)
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        $this->assertArrayHasKey('query', $parts);
        parse_str($parts['query'], $query);

        $this->assertArrayHasKey('state', $query);
        $this->assertEquals($query['state'], 'test');

        // ensure no error was returned
        $this->assertFalse(isset($query['error']));
        $this->assertFalse(isset($query['error_description']));
    }

    public function testSuccessfulRequestStripsExtraParameters()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = new Request(array(
            'client_id'     => 'Test Client ID', // valid client id
            'redirect_uri'  => 'http://adobe.com', // valid redirect URI
            'response_type' => 'code',
            'state'         => 'test',      // valid state string (just needs to be passed back to us)
            'fake'          => 'something', // extra query param
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $this->assertNotContains('error', $location);

        $parts = parse_url($location);
        $this->assertFalse(isset($parts['fake']));
        $this->assertArrayHasKey('query', $parts);
        parse_str($parts['query'], $query);

        $this->assertFalse(isset($parmas['fake']));
        $this->assertArrayHasKey('state', $query);
        $this->assertEquals($query['state'], 'test');
    }

    public function testSuccessfulOpenidConnectRequest()
    {
        $server = $this->getTestServer(array(
            'use_openid_connect' => true,
            'issuer' => 'bojanz',
        ));

        $request = new Request(array(
            'client_id'     => 'Test Client ID',
            'redirect_uri'  => 'http://adobe.com',
            'response_type' => 'code',
            'state'         => 'xyz',
            'scope'         => 'openid',
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        $this->assertArrayHasKey('query', $parts);
        $this->assertFalse(isset($parts['fragment']));

        // assert fragment is in "application/x-www-form-urlencoded" format
        parse_str($parts['query'], $query);
        $this->assertNotNull($query);
        $this->assertArrayHasKey('code', $query);

        // ensure no error was returned
        $this->assertFalse(isset($query['error']));
        $this->assertFalse(isset($query['error_description']));

        // confirm that the id_token has been created.
        $storage = $server->getStorage('authorization_code');
        $code = $storage->getAuthorizationCode($query['code']);
        $this->assertTrue(!empty($code['id_token']));
    }

    public function testCreateController()
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $controller = new AuthorizeController($storage);
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
