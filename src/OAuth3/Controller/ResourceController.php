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

use OAuth3\TokenType\TokenTypeInterface;
use OAuth3\Storage\AccessTokenInterface;
use OAuth3\ScopeInterface;
use OAuth3\RequestInterface;
use OAuth3\ResponseInterface;
use OAuth3\Scope;

/**
 * @see ResourceControllerInterface
 */
class ResourceController implements ResourceControllerInterface
{
    /**
     * @var array
     */
    private $token;

    /**
     * @var TokenTypeInterface
     */
    protected $tokenType;

    /**
     * @var AccessTokenInterface
     */
    protected $tokenStorage;

    /**
     * @var array
     */
    protected $config;

    /**
     * @var ScopeInterface
     */
    protected $scopeUtil;

    /**
     * Constructor
     *
     * @param TokenTypeInterface   $tokenType
     * @param AccessTokenInterface $tokenStorage
     * @param array                $config
     * @param ScopeInterface       $scopeUtil
     */
    public function __construct(TokenTypeInterface $tokenType, AccessTokenInterface $tokenStorage, $config = array(), ScopeInterface $scopeUtil = null)
    {
        $this->tokenType = $tokenType;
        $this->tokenStorage = $tokenStorage;

        $this->config = array_merge(array(
            'www_realm' => 'Service',
        ), $config);

        if (is_null($scopeUtil)) {
            $scopeUtil = new Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    /**
     * Verify the resource request
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @param null              $scope
     * @return bool
     */
    public function verifyResourceRequest(RequestInterface $request, ResponseInterface $response, $scope = null)
    {
        $token = $this->getAccessTokenData($request, $response);

        // Check if we have token data
        if (is_null($token)) {
            return false;
        }

        /**
         * Check scope, if provided
         * If token doesn't have a scope, it's null/empty, or it's insufficient, then throw 403
         * @see http://tools.ietf.org/html/rfc6750#section-3.1
         */
        if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->scopeUtil->checkScope($scope, $token["scope"]))) {
            $response->setError(403, 'insufficient_scope', 'The request requires higher privileges than provided by the access token');
            $response->addHttpHeaders(array(
                'WWW-Authenticate' => sprintf('%s realm="%s", scope="%s", error="%s", error_description="%s"',
                    $this->tokenType->getTokenType(),
                    $this->config['www_realm'],
                    $scope,
                    $response->getParameter('error'),
                    $response->getParameter('error_description')
                )
            ));

            return false;
        }

        // allow retrieval of the token
        $this->token = $token;

        return (bool) $token;
    }

    /**
     * Get access token data.
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @return array|null
     */
    public function getAccessTokenData(RequestInterface $request, ResponseInterface $response)
    {
        // Get the token parameter
        if ($token_param = $this->tokenType->getAccessTokenParameter($request, $response)) {
            // Get the stored token data (from the implementing subclass)
            // Check we have a well formed token
            // Check token expiration (expires is a mandatory paramter)
            if (!$token = $this->tokenStorage->getAccessToken($token_param)) {
                $response->setError(401, 'invalid_token', 'The access token provided is invalid');
            } elseif (!isset($token["expires"]) || !isset($token["client_id"])) {
                $response->setError(401, 'malformed_token', 'Malformed token (missing "expires")');
            } elseif (time() > $token["expires"]) {
                $response->setError(401, 'invalid_token', 'The access token provided has expired');
            } else {
                return $token;
            }
        }

        $authHeader = sprintf('%s realm="%s"', $this->tokenType->getTokenType(), $this->config['www_realm']);

        if ($error = $response->getParameter('error')) {
            $authHeader = sprintf('%s, error="%s"', $authHeader, $error);
            if ($error_description = $response->getParameter('error_description')) {
                $authHeader = sprintf('%s, error_description="%s"', $authHeader, $error_description);
            }
        }

        $response->addHttpHeaders(array('WWW-Authenticate' => $authHeader));

        return null;
    }

    /**
     * convenience method to allow retrieval of the token.
     *
     * @return array
     */
    public function getToken()
    {
        return $this->token;
    }
}
