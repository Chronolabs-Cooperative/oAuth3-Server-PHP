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


namespace OAuth2\Request;

use OAuth3\Request;
use OAuth3\RequestInterface;

/**
*
*/
class TestRequest extends Request implements RequestInterface
{
    public $query, $request, $server, $headers;

    public function __construct()
    {
        $this->query = $_GET;
        $this->request = $_POST;
        $this->server  = $_SERVER;
        $this->headers = array();
    }

    public function query($name, $default = null)
    {
        return isset($this->query[$name]) ? $this->query[$name] : $default;
    }

    public function request($name, $default = null)
    {
        return isset($this->request[$name]) ? $this->request[$name] : $default;
    }

    public function server($name, $default = null)
    {
        return isset($this->server[$name]) ? $this->server[$name] : $default;
    }

    public function getAllQueryParameters()
    {
        return $this->query;
    }

    public function setQuery(array $query)
    {
        $this->query = $query;
    }

    public function setMethod($method)
    {
        $this->server['REQUEST_METHOD'] = $method;
    }

    public function setPost(array $params)
    {
        $this->setMethod('POST');
        $this->request = $params;
    }

    public static function createPost(array $params = array())
    {
        $request = new self();
        $request->setPost($params);

        return $request;
    }
}
