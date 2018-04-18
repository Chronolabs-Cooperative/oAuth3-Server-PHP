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

/**
 * Interface which represents an object response.  Meant to handle and display the proper OAuth3 Responses
 * for errors and successes
 *
 * @see \OAuth3\Response
 */
interface ResponseInterface
{
    /**
     * @param array $parameters
     */
    public function addParameters(array $parameters);

    /**
     * @param array $httpHeaders
     */
    public function addHttpHeaders(array $httpHeaders);

    /**
     * @param int $statusCode
     */
    public function setStatusCode($statusCode);

    /**
     * @param int    $statusCode
     * @param string $name
     * @param string $description
     * @param string $uri
     * @return mixed
     */
    public function setError($statusCode, $name, $description = null, $uri = null);

    /**
     * @param int    $statusCode
     * @param string $url
     * @param string $state
     * @param string $error
     * @param string $errorDescription
     * @param string $errorUri
     * @return mixed
     */
    public function setRedirect($statusCode, $url, $state = null, $error = null, $errorDescription = null, $errorUri = null);

    /**
     * @param string $name
     * @return mixed
     */
    public function getParameter($name);
}
