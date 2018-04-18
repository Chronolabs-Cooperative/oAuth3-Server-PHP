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


namespace OAuth3\Storage;

use OAuth3\Encryption\EncryptionInterface;
use OAuth3\Encryption\Jwt;

/**
 * @author Brent Shaffer <bshafs@gmail.com>
 */
class JwtAccessToken implements JwtAccessTokenInterface
{
    protected $publicKeyStorage;
    protected $tokenStorage;
    protected $encryptionUtil;

    /**
     * @param OAuth3\Encryption\PublicKeyInterface  $publicKeyStorage the public key encryption to use
     * @param OAuth3\Storage\AccessTokenInterface   $tokenStorage     OPTIONAL persist the access token to another storage. This is useful if
     *                                                                you want to retain access token grant information somewhere, but
     *                                                                is not necessary when using this grant type.
     * @param OAuth3\Encryption\EncryptionInterface $encryptionUtil   OPTIONAL class to use for "encode" and "decode" functions.
     */
    public function __construct(PublicKeyInterface $publicKeyStorage, AccessTokenInterface $tokenStorage = null, EncryptionInterface $encryptionUtil = null)
    {
        $this->publicKeyStorage = $publicKeyStorage;
        $this->tokenStorage = $tokenStorage;
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt;
        }
        $this->encryptionUtil = $encryptionUtil;
    }

    public function getAccessToken($oauth_token)
    {
        // just decode the token, don't verify
        if (!$tokenData = $this->encryptionUtil->decode($oauth_token, null, false)) {
            return false;
        }

        $client_id  = isset($tokenData['aud']) ? $tokenData['aud'] : null;
        $public_key = $this->publicKeyStorage->getPublicKey($client_id);
        $algorithm  = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);

        // now that we have the client_id, verify the token
        if (false === $this->encryptionUtil->decode($oauth_token, $public_key, array($algorithm))) {
            return false;
        }

        // normalize the JWT claims to the format expected by other components in this library
        return $this->convertJwtToOAuth3($tokenData);
    }

    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = null)
    {
        if ($this->tokenStorage) {
            return $this->tokenStorage->setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope);
        }
    }

    public function unsetAccessToken($access_token)
    {
        if ($this->tokenStorage) {
            return $this->tokenStorage->unsetAccessToken($access_token);
        }
    }


    // converts a JWT access token into an OAuth3-friendly format
    protected function convertJwtToOAuth3($tokenData)
    {
        $keyMapping = array(
            'aud' => 'client_id',
            'exp' => 'expires',
            'sub' => 'user_id'
        );

        foreach ($keyMapping as $jwtKey => $OAuth3Key) {
            if (isset($tokenData[$jwtKey])) {
                $tokenData[$OAuth3Key] = $tokenData[$jwtKey];
                unset($tokenData[$jwtKey]);
            }
        }

        return $tokenData;
    }
}