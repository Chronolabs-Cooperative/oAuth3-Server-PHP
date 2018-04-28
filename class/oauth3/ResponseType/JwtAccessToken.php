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


namespace OAuth3\ResponseType;

use OAuth3\Encryption\EncryptionInterface;
use OAuth3\Encryption\Jwt;
use OAuth3\Storage\AccessTokenInterface as AccessTokenStorageInterface;
use OAuth3\Storage\RefreshTokenInterface;
use OAuth3\Storage\PublicKeyInterface;
use OAuth3\Storage\Memory;

class JwtAccessToken extends AccessToken
{
    protected $publicKeyStorage;
    protected $encryptionUtil;

    /**
     * @param PublicKeyInterface          $publicKeyStorage -
     * @param AccessTokenStorageInterface $tokenStorage     -
     * @param RefreshTokenInterface       $refreshStorage   -
     * @param array                       $config           - array with key store_encrypted_token_string (bool true)
     *                                                        whether the entire encrypted string is stored,
     *                                                        or just the token ID is stored
     * @param EncryptionInterface         $encryptionUtil   -
     */
    public function __construct(PublicKeyInterface $publicKeyStorage = null, AccessTokenStorageInterface $tokenStorage = null, RefreshTokenInterface $refreshStorage = null, array $config = array(), EncryptionInterface $encryptionUtil = null)
    {
        $this->publicKeyStorage = $publicKeyStorage;
        $config = array_merge(array(
            'store_encrypted_token_string' => true,
            'issuer' => ''
        ), $config);
        if (is_null($tokenStorage)) {
            // a pass-thru, so we can call the parent constructor
            $tokenStorage = new Memory();
        }
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt();
        }
        $this->encryptionUtil = $encryptionUtil;
        parent::__construct($tokenStorage, $refreshStorage, $config);
    }

    /**
     * Handle the creation of access token, also issue refresh token if supported / desirable.
     *
     * @param mixed  $client_id           - Client identifier related to the access token.
     * @param mixed  $user_id             - User ID associated with the access token
     * @param string $scope               - (optional) Scopes to be stored in space-separated string.
     * @param bool   $includeRefreshToken - If true, a new refresh_token will be added to the response
     * @return array                      - The access token
     *
     * @see http://tools.ietf.org/html/rfc6749#section-5
     * @ingroup OAuth3_section_5
     */
    public function createAccessToken($client_id, $user_id, $scope = null, $includeRefreshToken = true)
    {
        // payload to encrypt
        $payload = $this->createPayload($client_id, $user_id, $scope);

        /*
         * Encode the payload data into a single JWT access_token string
         */
        $access_token = $this->encodeToken($payload, $client_id);

        /*
         * Save the token to a secondary storage.  This is implemented on the
         * OAuth3\Storage\JwtAccessToken side, and will not actually store anything,
         * if no secondary storage has been supplied
         */
        $token_to_store = $this->config['store_encrypted_token_string'] ? $access_token : $payload['id'];
        $this->tokenStorage->setAccessToken($token_to_store, $client_id, $user_id, $this->config['access_lifetime'] ? time() + $this->config['access_lifetime'] : null, $scope);

        // token to return to the client
        $token = array(
            'access_token' => $access_token,
            'expires_in' => $this->config['access_lifetime'],
            'token_type' => $this->config['token_type'],
            'scope' => $scope
        );

        /*
         * Issue a refresh token also, if we support them
         *
         * Refresh Tokens are considered supported if an instance of OAuth3\Storage\RefreshTokenInterface
         * is supplied in the constructor
         */
        if ($includeRefreshToken && $this->refreshStorage) {
            $refresh_token = $this->generateRefreshToken();
            $expires = 0;
            if ($this->config['refresh_token_lifetime'] > 0) {
                $expires = time() + $this->config['refresh_token_lifetime'];
            }
            $this->refreshStorage->setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope);
            $token['refresh_token'] = $refresh_token;
        }

        return $token;
    }

    /**
     * @param array $token
     * @param mixed $client_id
     * @return mixed
     */
    protected function encodeToken(array $token, $client_id = null)
    {
        $private_key = $this->publicKeyStorage->getPrivateKey($client_id);
        $algorithm   = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);

        return $this->encryptionUtil->encode($token, $private_key, $algorithm);
    }

    /**
     * This function can be used to create custom JWT payloads
     *
     * @param mixed  $client_id           - Client identifier related to the access token.
     * @param mixed  $user_id             - User ID associated with the access token
     * @param string $scope               - (optional) Scopes to be stored in space-separated string.
     * @return array                      - The access token
     */
    protected function createPayload($client_id, $user_id, $scope = null)
    {
        // token to encrypt
        $expires = time() + $this->config['access_lifetime'];
        $id = $this->generateAccessToken();

        $payload = array(
            'id'         => $id, // for BC (see #591)
            'jti'        => $id,
            'iss'        => $this->config['issuer'],
            'aud'        => $client_id,
            'sub'        => $user_id,
            'exp'        => $expires,
            'iat'        => time(),
            'token_type' => $this->config['token_type'],
            'scope'      => $scope
        );
        
        if (isset($this->config['jwt_extra_payload_callable'])) {
            if (!is_callable($this->config['jwt_extra_payload_callable'])) {
                throw new \InvalidArgumentException('jwt_extra_payload_callable is not callable');
            }
            
            $extra = call_user_func($this->config['jwt_extra_payload_callable'], $client_id, $user_id, $scope);
            
            if (!is_array($extra)) {
                throw new \InvalidArgumentException('jwt_extra_payload_callable must return array');
            }
            
            $payload = array_merge($extra, $payload);
        }
        
        return $payload;
    }
}
