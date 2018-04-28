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


namespace OAuth3\OpenID\Controller;

use OAuth3\Controller\AuthorizeController as BaseAuthorizeController;
use OAuth3\RequestInterface;
use OAuth3\ResponseInterface;

/**
 * @see OAuth3\Controller\AuthorizeControllerInterface
 */
class AuthorizeController extends BaseAuthorizeController implements AuthorizeControllerInterface
{
    /**
     * @var mixed
     */
    private $nonce;

    /**
     * Set not authorized response
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @param string            $redirect_uri
     * @param null              $user_id
     */
    protected function setNotAuthorizedResponse(RequestInterface $request, ResponseInterface $response, $redirect_uri, $user_id = null)
    {
        $prompt = $request->query('prompt', 'consent');
        if ($prompt == 'none') {
            if (is_null($user_id)) {
                $error = 'login_required';
                $error_message = 'The user must log in';
            } else {
                $error = 'interaction_required';
                $error_message = 'The user must grant access to your application';
            }
        } else {
            $error = 'consent_required';
            $error_message = 'The user denied access to your application';
        }

        $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $this->getState(), $error, $error_message);
    }

    /**
     * @TODO: add dependency injection for the parameters in this method
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @param mixed $user_id
     * @return array
     */
    protected function buildAuthorizeParameters($request, $response, $user_id)
    {
        if (!$params = parent::buildAuthorizeParameters($request, $response, $user_id)) {
            return;
        }

        // Generate an id token if needed.
        if ($this->needsIdToken($this->getScope()) && $this->getResponseType() == self::RESPONSE_TYPE_AUTHORIZATION_CODE) {
            $params['id_token'] = $this->responseTypes['id_token']->createIdToken($this->getClientId(), $user_id, $this->nonce);
        }

        // add the nonce to return with the redirect URI
        $params['nonce'] = $this->nonce;

        return $params;
    }

    /**
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return bool
     */
    public function validateAuthorizeRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!parent::validateAuthorizeRequest($request, $response)) {
            return false;
        }

        $nonce = $request->query('nonce');

        // Validate required nonce for "id_token" and "id_token token"
        if (!$nonce && in_array($this->getResponseType(), array(self::RESPONSE_TYPE_ID_TOKEN, self::RESPONSE_TYPE_ID_TOKEN_TOKEN))) {
            $response->setError(400, 'invalid_nonce', 'This application requires you specify a nonce parameter');

            return false;
        }

        $this->nonce = $nonce;

        return true;
    }

    /**
     * Array of valid response types
     *
     * @return array
     */
    protected function getValidResponseTypes()
    {
        return array(
            self::RESPONSE_TYPE_ACCESS_TOKEN,
            self::RESPONSE_TYPE_AUTHORIZATION_CODE,
            self::RESPONSE_TYPE_ID_TOKEN,
            self::RESPONSE_TYPE_ID_TOKEN_TOKEN,
            self::RESPONSE_TYPE_CODE_ID_TOKEN,
        );
    }

    /**
     * Returns whether the current request needs to generate an id token.
     *
     * ID Tokens are a part of the OpenID Connect specification, so this
     * method checks whether OpenID Connect is enabled in the server settings
     * and whether the openid scope was requested.
     *
     * @param string $request_scope - A space-separated string of scopes.
     * @return boolean - TRUE if an id token is needed, FALSE otherwise.
     */
    public function needsIdToken($request_scope)
    {
        // see if the "openid" scope exists in the requested scope
        return $this->scopeUtil->checkScope('openid', $request_scope);
    }

    /**
     * @return mixed
     */
    public function getNonce()
    {
        return $this->nonce;
    }
}
