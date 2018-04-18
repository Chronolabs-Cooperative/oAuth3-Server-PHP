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


namespace OAuth3\TokenType;

use OAuth3\Request\TestRequest;
use OAuth3\Response;
use PHPUnit\Framework\TestCase;

class BearerTest extends TestCase
{
    public function testValidContentTypeWithCharset()
    {
        $bearer = new Bearer();
        $request = TestRequest::createPost(array(
            'access_token' => 'ThisIsMyAccessToken'
        ));
        $request->server['CONTENT_TYPE'] = 'application/x-www-form-urlencoded; charset=UTF-8';

        $param = $bearer->getAccessTokenParameter($request, $response = new Response());
        $this->assertEquals($param, 'ThisIsMyAccessToken');
    }

    public function testInvalidContentType()
    {
        $bearer = new Bearer();
        $request = TestRequest::createPost(array(
            'access_token' => 'ThisIsMyAccessToken'
        ));
        $request->server['CONTENT_TYPE'] = 'application/json; charset=UTF-8';

        $param = $bearer->getAccessTokenParameter($request, $response = new Response());
        $this->assertNull($param);
        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'The content type for POST requests must be "application/x-www-form-urlencoded"');
    }

    public function testValidRequestUsingAuthorizationHeader()
    {
        $bearer = new Bearer();
        $request = new TestRequest();
        $request->headers['AUTHORIZATION'] = 'Bearer MyToken';
        $request->server['CONTENT_TYPE'] = 'application/x-www-form-urlencoded; charset=UTF-8';

        $param = $bearer->getAccessTokenParameter($request, $response = new Response());
        $this->assertEquals('MyToken', $param);
    }

    public function testValidRequestUsingAuthorizationHeaderCaseInsensitive()
    {
        $bearer = new Bearer();
        $request = new TestRequest();
        $request->server['CONTENT_TYPE'] = 'application/x-www-form-urlencoded; charset=UTF-8';
        $request->headers['Authorization'] = 'Bearer MyToken';

        $param = $bearer->getAccessTokenParameter($request, $response = new Response());
        $this->assertEquals('MyToken', $param);
    }
}
