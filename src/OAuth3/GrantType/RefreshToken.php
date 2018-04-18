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

use OAuth3\Storage\RefreshTokenInterface;
use OAuth3\ResponseType\AccessTokenInterface;
use OAuth3\RequestInterface;
use OAuth3\ResponseInterface;

/**
 * @author Brent Shaffer <bshafs@gmail.com>
 */
class RefreshToken implements GrantTypeInterface
{
    /**
     * @var array
     */
    private $refreshToken;

    /**
     * @var RefreshTokenInterface
     */
    protected $storage;

    /**
     * @var array
     */
    protected $config;

    /**
     * @param RefreshTokenInterface $storage - REQUIRED Storage class for retrieving refresh token information
     * @param array                 $config  - OPTIONAL Configuration options for the server
     * @code
     *     $config = array(
     *         'always_issue_new_refresh_token' => true, // whether to issue a new refresh token upon successful token request
     *         'unset_refresh_token_after_use' => true // whether to unset the refresh token after after using
     *     );
     * @endcode
     */
    public function __construct(RefreshTokenInterface $storage, $config = array())
    {
        $this->config = array_merge(array(
            'always_issue_new_refresh_token' => false,
            'unset_refresh_token_after_use' => true
        ), $config);

        // to preserve B.C. with v1.6
        // @see https://github.com/bshaffer/OAuth3-server-php/pull/580
        // @todo - remove in v2.0
        if (isset($config['always_issue_new_refresh_token']) && !isset($config['unset_refresh_token_after_use'])) {
            $this->config['unset_refresh_token_after_use'] = $config['always_issue_new_refresh_token'];
        }

        $this->storage = $storage;
    }

    /**
     * @return string
     */
    public function getQueryStringIdentifier()
    {
        return 'refresh_token';
    }

    /**
     * Validate the OAuth request
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @return bool|mixed|null
     */
    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!$request->request("refresh_token")) {
            $response->setError(400, 'invalid_request', 'Missing parameter: "refresh_token" is required');

            return null;
        }

        if (!$refreshToken = $this->storage->getRefreshToken($request->request("refresh_token"))) {
            $response->setError(400, 'invalid_grant', 'Invalid refresh token');

            return null;
        }

        if ($refreshToken['expires'] > 0 && $refreshToken["expires"] < time()) {
            $response->setError(400, 'invalid_grant', 'Refresh token has expired');

            return null;
        }

        // store the refresh token locally so we can delete it when a new refresh token is generated
        $this->refreshToken = $refreshToken;

        return true;
    }

    /**
     * Get client id
     *
     * @return mixed
     */
    public function getClientId()
    {
        return $this->refreshToken['client_id'];
    }

    /**
     * Get user id
     *
     * @return mixed|null
     */
    public function getUserId()
    {
        return isset($this->refreshToken['user_id']) ? $this->refreshToken['user_id'] : null;
    }

    /**
     * Get scope
     *
     * @return null|string
     */
    public function getScope()
    {
        return isset($this->refreshToken['scope']) ? $this->refreshToken['scope'] : null;
    }

    /**
     * Create access token
     *
     * @param AccessTokenInterface $accessToken
     * @param mixed                $client_id   - client identifier related to the access token.
     * @param mixed                $user_id     - user id associated with the access token
     * @param string               $scope       - scopes to be stored in space-separated string.
     * @return array
     */
    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        /*
         * It is optional to force a new refresh token when a refresh token is used.
         * However, if a new refresh token is issued, the old one MUST be expired
         * @see http://tools.ietf.org/html/rfc6749#section-6
         */
        $issueNewRefreshToken = $this->config['always_issue_new_refresh_token'];
        $unsetRefreshToken = $this->config['unset_refresh_token_after_use'];
        $token = $accessToken->createAccessToken($client_id, $user_id, $scope, $issueNewRefreshToken);

        if ($unsetRefreshToken) {
            $this->storage->unsetRefreshToken($this->refreshToken['refresh_token']);
        }

        return $token;
    }
}
