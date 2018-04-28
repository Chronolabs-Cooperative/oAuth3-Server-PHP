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


namespace OAuth3\OpenID\ResponseType;

use OAuth3\ResponseType\AuthorizationCode as BaseAuthorizationCode;
use OAuth3\OpenID\Storage\AuthorizationCodeInterface as AuthorizationCodeStorageInterface;

/**
 * @author Brent Shaffer <bshafs@gmail.com>
 */
class AuthorizationCode extends BaseAuthorizationCode implements AuthorizationCodeInterface
{
    /**
     * Constructor
     *
     * @param AuthorizationCodeStorageInterface $storage
     * @param array $config
     */
    public function __construct(AuthorizationCodeStorageInterface $storage, array $config = array())
    {
        parent::__construct($storage, $config);
    }

    /**
     * @param $params
     * @param null $user_id
     * @return array
     */
    public function getAuthorizeResponse($params, $user_id = null)
    {
        // build the URL to redirect to
        $result = array('query' => array());

        $params += array('scope' => null, 'state' => null, 'id_token' => null);

        $result['query']['code'] = $this->createAuthorizationCode($params['client_id'], $user_id, $params['redirect_uri'], $params['scope'], $params['id_token']);

        if (isset($params['state'])) {
            $result['query']['state'] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }

    /**
     * Handle the creation of the authorization code.
     *
     * @param mixed $client_id - Client identifier related to the authorization code
     * @param mixed $user_id - User ID associated with the authorization code
     * @param string $redirect_uri - An absolute URI to which the authorization server will redirect the
     *                               user-agent to when the end-user authorization step is completed.
     * @param string $scope - OPTIONAL Scopes to be stored in space-separated string.
     * @param string $id_token - OPTIONAL The OpenID Connect id_token.
     *
     * @return string
     * @see http://tools.ietf.org/html/rfc6749#section-4
     * @ingroup OAuth3_section_4
     */
    public function createAuthorizationCode($client_id, $user_id, $redirect_uri, $scope = null, $id_token = null)
    {
        $code = $this->generateAuthorizationCode();
        $this->storage->setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, time() + $this->config['auth_code_lifetime'], $scope, $id_token);

        return $code;
    }
}
