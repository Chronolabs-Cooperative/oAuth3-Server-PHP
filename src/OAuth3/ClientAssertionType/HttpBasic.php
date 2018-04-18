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


namespace OAuth3\ClientAssertionType;

use OAuth3\Storage\ClientCredentialsInterface;
use OAuth3\RequestInterface;
use OAuth3\ResponseInterface;
use LogicException;

/**
 * Validate a client via Http Basic authentication
 *
 * @author    Brent Shaffer <bshafs@gmail.com>
 */
class HttpBasic implements ClientAssertionTypeInterface
{
    private $clientData;

    protected $storage;
    protected $config;

    /**
     * Config array $config should look as follows:
     * @code
     *     $config = array(
     *         'allow_credentials_in_request_body' => true, // whether to look for credentials in the POST body in addition to the Authorize HTTP Header
     *         'allow_public_clients'  => true              // if true, "public clients" (clients without a secret) may be authenticated
     *     );
     * @endcode
     *
     * @param ClientCredentialsInterface $storage Storage
     * @param array                      $config  Configuration options for the server
     */
    public function __construct(ClientCredentialsInterface $storage, array $config = array())
    {
        $this->storage = $storage;
        $this->config = array_merge(array(
            'allow_credentials_in_request_body' => true,
            'allow_public_clients' => true,
        ), $config);
    }

    /**
     * Validate the OAuth request
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return bool|mixed
     * @throws LogicException
     */
    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!$clientData = $this->getClientCredentials($request, $response)) {
            return false;
        }

        if (!isset($clientData['client_id'])) {
            throw new LogicException('the clientData array must have "client_id" set');
        }

        if (!isset($clientData['client_secret']) || $clientData['client_secret'] == '') {
            if (!$this->config['allow_public_clients']) {
                $response->setError(400, 'invalid_client', 'client credentials are required');

                return false;
            }

            if (!$this->storage->isPublicClient($clientData['client_id'])) {
                $response->setError(400, 'invalid_client', 'This client is invalid or must authenticate using a client secret');

                return false;
            }
        } elseif ($this->storage->checkClientCredentials($clientData['client_id'], $clientData['client_secret']) === false) {
            $response->setError(400, 'invalid_client', 'The client credentials are invalid');

            return false;
        }

        $this->clientData = $clientData;

        return true;
    }

    /**
     * Get the client id
     *
     * @return mixed
     */
    public function getClientId()
    {
        return $this->clientData['client_id'];
    }

    /**
     * Internal function used to get the client credentials from HTTP basic
     * auth or POST data.
     *
     * According to the spec (draft 20), the client_id can be provided in
     * the Basic Authorization header (recommended) or via GET/POST.
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @return array|null A list containing the client identifier and password, for example:
     * @code
     *     return array(
     *         "client_id"     => CLIENT_ID,        // REQUIRED the client id
     *         "client_secret" => CLIENT_SECRET,    // OPTIONAL the client secret (may be omitted for public clients)
     *     );
     * @endcode
     *
     * @see http://tools.ietf.org/html/rfc6749#section-2.3.1
     *
     * @ingroup OAuth3_section_2
     */
    public function getClientCredentials(RequestInterface $request, ResponseInterface $response = null)
    {
        if (!is_null($request->headers('PHP_AUTH_USER')) && !is_null($request->headers('PHP_AUTH_PW'))) {
            return array('client_id' => $request->headers('PHP_AUTH_USER'), 'client_secret' => $request->headers('PHP_AUTH_PW'));
        }

        if ($this->config['allow_credentials_in_request_body']) {
            // Using POST for HttpBasic authorization is not recommended, but is supported by specification
            if (!is_null($request->request('client_id'))) {
                /**
                 * client_secret can be null if the client's password is an empty string
                 * @see http://tools.ietf.org/html/rfc6749#section-2.3.1
                 */
                return array('client_id' => $request->request('client_id'), 'client_secret' => $request->request('client_secret'));
            }
        }

        if ($response) {
            $message = $this->config['allow_credentials_in_request_body'] ? ' or body' : '';
            $response->setError(400, 'invalid_client', 'Client credentials were not found in the headers'.$message);
        }

        return null;
    }
}
