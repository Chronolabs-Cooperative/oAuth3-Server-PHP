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

use OAuth3\RequestInterface;
use OAuth3\ResponseInterface;

/**
 *  This controller is called when a "resource" is requested.
 *  call verifyResourceRequest in order to determine if the request
 *  contains a valid token.
 *
 * @code
 *     if (!$resourceController->verifyResourceRequest(OAuth3\Request::createFromGlobals(), $response = new OAuth3\Response())) {
 *         $response->send(); // authorization failed
 *         die();
 *     }
 *     return json_encode($resource); // valid token!  Send the stuff!
 * @endcode
 */
interface ResourceControllerInterface
{
    /**
     * Verify the resource request
     *
     * @param RequestInterface  $request  - Request object
     * @param ResponseInterface $response - Response object
     * @param string            $scope
     * @return mixed
     */
    public function verifyResourceRequest(RequestInterface $request, ResponseInterface $response, $scope = null);

    /**
     * Get access token data.
     *
     * @param RequestInterface  $request  - Request object
     * @param ResponseInterface $response - Response object
     * @return mixed
     */
    public function getAccessTokenData(RequestInterface $request, ResponseInterface $response);
}
