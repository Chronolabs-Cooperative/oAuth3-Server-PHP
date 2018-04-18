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
 *  This controller is called when a user should be authorized
 *  by an authorization server.  As OAuth3 does not handle
 *  authorization directly, this controller ensures the request is valid, but
 *  requires the application to determine the value of $is_authorized
 *
 *  @code
 *      $user_id = $this->somehowDetermineUserId();
 *      $is_authorized = $this->somehowDetermineUserAuthorization();
 *      $response = new OAuth3\Response();
 *      $authorizeController->handleAuthorizeRequest(
 *          OAuth3\Request::createFromGlobals(),
 *          $response,
 *          $is_authorized,
 *          $user_id
 *      );
 *      $response->send();
 * @endcode
 */
interface AuthorizeControllerInterface
{
    /**
     * List of possible authentication response types.
     * The "authorization_code" mechanism exclusively supports 'code'
     * and the "implicit" mechanism exclusively supports 'token'.
     *
     * @var string
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.1
     * @see http://tools.ietf.org/html/rfc6749#section-4.2.1
     */
    const RESPONSE_TYPE_AUTHORIZATION_CODE = 'code';
    const RESPONSE_TYPE_ACCESS_TOKEN = 'token';

    /**
     * Handle the OAuth request
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @param $is_authorized
     * @param null $user_id
     * @return mixed
     */
    public function handleAuthorizeRequest(RequestInterface $request, ResponseInterface $response, $is_authorized, $user_id = null);

    /**
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return bool
     */
    public function validateAuthorizeRequest(RequestInterface $request, ResponseInterface $response);
}
