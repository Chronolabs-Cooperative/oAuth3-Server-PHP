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


namespace OAuth2\ResponseType;

use OAuth3\Server;
use OAuth3\Response;
use OAuth3\Request\TestRequest;
use OAuth3\Storage\Bootstrap;
use OAuth3\Storage\JwtAccessToken as JwtAccessTokenStorage;
use OAuth3\GrantType\ClientCredentials;
use OAuth3\GrantType\UserCredentials;
use OAuth3\GrantType\RefreshToken;
use OAuth3\Encryption\Jwt;
use PHPUnit\Framework\TestCase;

class JwtAccessTokenTest extends TestCase
{
    public function testCreateAccessToken()
    {
        $server = $this->getTestServer();
        $jwtResponseType = $server->getResponseType('token');

        $accessToken = $jwtResponseType->createAccessToken('Test Client ID', 123, 'test', false);
        $jwt = new Jwt;
        $decodedAccessToken = $jwt->decode($accessToken['access_token'], null, false);

        $this->assertArrayHasKey('id', $decodedAccessToken);
        $this->assertArrayHasKey('jti', $decodedAccessToken);
        $this->assertArrayHasKey('iss', $decodedAccessToken);
        $this->assertArrayHasKey('aud', $decodedAccessToken);
        $this->assertArrayHasKey('exp', $decodedAccessToken);
        $this->assertArrayHasKey('iat', $decodedAccessToken);
        $this->assertArrayHasKey('token_type', $decodedAccessToken);
        $this->assertArrayHasKey('scope', $decodedAccessToken);

        $this->assertEquals('https://api.example.com', $decodedAccessToken['iss']);
        $this->assertEquals('Test Client ID', $decodedAccessToken['aud']);
        $this->assertEquals(123, $decodedAccessToken['sub']);
        $delta = $decodedAccessToken['exp'] - $decodedAccessToken['iat'];
        $this->assertEquals(3600, $delta);
        $this->assertEquals($decodedAccessToken['id'], $decodedAccessToken['jti']);
    }
    
    public function testExtraPayloadCallback()
    {
        $jwtconfig = array('jwt_extra_payload_callable' => function() {
            return array('custom_param' => 'custom_value');
        });
        
        $server = $this->getTestServer($jwtconfig);
        $jwtResponseType = $server->getResponseType('token');
        
        $accessToken = $jwtResponseType->createAccessToken('Test Client ID', 123, 'test', false);
        $jwt = new Jwt;
        $decodedAccessToken = $jwt->decode($accessToken['access_token'], null, false);
        
        $this->assertArrayHasKey('custom_param', $decodedAccessToken);
        $this->assertEquals('custom_value', $decodedAccessToken['custom_param']);
    }

    public function testGrantJwtAccessToken()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'client_credentials', // valid grant type
            'client_id'     => 'Test Client ID',     // valid client id
            'client_secret' => 'TestSecret',         // valid client secret
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertNotNull($response->getParameter('access_token'));
        $this->assertEquals(2, substr_count($response->getParameter('access_token'), '.'));
    }

    public function testAccessResourceWithJwtAccessToken()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'client_credentials', // valid grant type
            'client_id'     => 'Test Client ID',     // valid client id
            'client_secret' => 'TestSecret',         // valid client secret
        ));
        $server->handleTokenRequest($request, $response = new Response());
        $this->assertNotNull($JwtAccessToken = $response->getParameter('access_token'));

        // make a call to the resource server using the crypto token
        $request = TestRequest::createPost(array(
            'access_token' => $JwtAccessToken,
        ));

        $this->assertTrue($server->verifyResourceRequest($request));
    }

    public function testAccessResourceWithJwtAccessTokenUsingSecondaryStorage()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'client_credentials', // valid grant type
            'client_id'     => 'Test Client ID',     // valid client id
            'client_secret' => 'TestSecret',         // valid client secret
        ));
        $server->handleTokenRequest($request, $response = new Response());
        $this->assertNotNull($JwtAccessToken = $response->getParameter('access_token'));

        // make a call to the resource server using the crypto token
        $request = TestRequest::createPost(array(
            'access_token' => $JwtAccessToken,
        ));

        // create a resource server with the "memory" storage from the grant server
        $resourceServer = new Server($server->getStorage('client_credentials'));

        $this->assertTrue($resourceServer->verifyResourceRequest($request));
    }

    public function testJwtAccessTokenWithRefreshToken()
    {
        $server = $this->getTestServer();

        // add "UserCredentials" grant type and "JwtAccessToken" response type
        // and ensure "JwtAccessToken" response type has "RefreshToken" storage
        $memoryStorage = Bootstrap::getInstance()->getMemoryStorage();
        $server->addGrantType(new UserCredentials($memoryStorage));
        $server->addGrantType(new RefreshToken($memoryStorage));
        $server->addResponseType(new JwtAccessToken($memoryStorage, $memoryStorage, $memoryStorage), 'token');

        $request = TestRequest::createPost(array(
            'grant_type'    => 'password',         // valid grant type
            'client_id'     => 'Test Client ID',   // valid client id
            'client_secret' => 'TestSecret',       // valid client secret
            'username'      => 'test-username',    // valid username
            'password'      => 'testpass',         // valid password
        ));

        // make the call to grant a crypto token
        $server->handleTokenRequest($request, $response = new Response());
        $this->assertNotNull($JwtAccessToken = $response->getParameter('access_token'));
        $this->assertNotNull($refreshToken = $response->getParameter('refresh_token'));

        // decode token and make sure refresh_token isn't set
        list($header, $payload, $signature) = explode('.', $JwtAccessToken);
        $decodedToken = json_decode(base64_decode($payload), true);
        $this->assertFalse(array_key_exists('refresh_token', $decodedToken));

        // use the refresh token to get another access token
        $request = TestRequest::createPost(array(
            'grant_type'    => 'refresh_token',
            'client_id'     => 'Test Client ID',   // valid client id
            'client_secret' => 'TestSecret',       // valid client secret
            'refresh_token' => $refreshToken,
        ));

        $server->handleTokenRequest($request, $response = new Response());
        $this->assertNotNull($response->getParameter('access_token'));
    }

    private function getTestServer($jwtconfig = array())
    {
        $memoryStorage = Bootstrap::getInstance()->getMemoryStorage();

        $storage = array(
            'access_token' => new JwtAccessTokenStorage($memoryStorage),
            'client' => $memoryStorage,
            'client_credentials' => $memoryStorage,
        );
        $server = new Server($storage);
        $server->addGrantType(new ClientCredentials($memoryStorage));

        // make the "token" response type a JwtAccessToken
        $config = array_merge(array('issuer' => 'https://api.example.com'), $jwtconfig);
        $server->addResponseType(new JwtAccessToken($memoryStorage, $memoryStorage, null, $config));

        return $server;
    }
}
