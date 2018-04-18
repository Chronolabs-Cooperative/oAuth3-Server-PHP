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

use OAuth3\Encryption\EncryptionInterface;
use OAuth3\Encryption\Jwt;
use OAuth3\Storage\PublicKeyInterface;
use OAuth3\OpenID\Storage\UserClaimsInterface;
use LogicException;

class IdToken implements IdTokenInterface
{
    /**
     * @var UserClaimsInterface
     */
    protected $userClaimsStorage;
    /**
     * @var PublicKeyInterface
     */
    protected $publicKeyStorage;

    /**
     * @var array
     */
    protected $config;

    /**
     * @var EncryptionInterface
     */
    protected $encryptionUtil;

    /**
     * Constructor
     *
     * @param UserClaimsInterface $userClaimsStorage
     * @param PublicKeyInterface $publicKeyStorage
     * @param array $config
     * @param EncryptionInterface $encryptionUtil
     * @throws LogicException
     */
    public function __construct(UserClaimsInterface $userClaimsStorage, PublicKeyInterface $publicKeyStorage, array $config = array(), EncryptionInterface $encryptionUtil = null)
    {
        $this->userClaimsStorage = $userClaimsStorage;
        $this->publicKeyStorage = $publicKeyStorage;
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt();
        }
        $this->encryptionUtil = $encryptionUtil;

        if (!isset($config['issuer'])) {
            throw new LogicException('config parameter "issuer" must be set');
        }
        $this->config = array_merge(array(
            'id_lifetime' => 3600,
        ), $config);
    }

    /**
     * @param array $params
     * @param null $userInfo
     * @return array|mixed
     */
    public function getAuthorizeResponse($params, $userInfo = null)
    {
        // build the URL to redirect to
        $result = array('query' => array());
        $params += array('scope' => null, 'state' => null, 'nonce' => null);

        // create the id token.
        list($user_id, $auth_time) = $this->getUserIdAndAuthTime($userInfo);
        $userClaims = $this->userClaimsStorage->getUserClaims($user_id, $params['scope']);

        $id_token = $this->createIdToken($params['client_id'], $userInfo, $params['nonce'], $userClaims, null);
        $result["fragment"] = array('id_token' => $id_token);
        if (isset($params['state'])) {
            $result["fragment"]["state"] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }

    /**
     * Create id token
     *
     * @param string $client_id
     * @param mixed  $userInfo
     * @param mixed  $nonce
     * @param mixed  $userClaims
     * @param mixed  $access_token
     * @return mixed|string
     */
    public function createIdToken($client_id, $userInfo, $nonce = null, $userClaims = null, $access_token = null)
    {
        // pull auth_time from user info if supplied
        list($user_id, $auth_time) = $this->getUserIdAndAuthTime($userInfo);

        $token = array(
            'iss'        => $this->config['issuer'],
            'sub'        => $user_id,
            'aud'        => $client_id,
            'iat'        => time(),
            'exp'        => time() + $this->config['id_lifetime'],
            'auth_time'  => $auth_time,
        );

        if ($nonce) {
            $token['nonce'] = $nonce;
        }

        if ($userClaims) {
            $token += $userClaims;
        }

        if ($access_token) {
            $token['at_hash'] = $this->createAtHash($access_token, $client_id);
        }

        return $this->encodeToken($token, $client_id);
    }

    /**
     * @param $access_token
     * @param null $client_id
     * @return mixed|string
     */
    protected function createAtHash($access_token, $client_id = null)
    {
        // maps HS256 and RS256 to sha256, etc.
        $algorithm = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);
        $hash_algorithm = 'sha' . substr($algorithm, 2);
        $hash = hash($hash_algorithm, $access_token, true);
        $at_hash = substr($hash, 0, strlen($hash) / 2);

        return $this->encryptionUtil->urlSafeB64Encode($at_hash);
    }

    /**
     * @param array $token
     * @param null $client_id
     * @return mixed|string
     */
    protected function encodeToken(array $token, $client_id = null)
    {
        $private_key = $this->publicKeyStorage->getPrivateKey($client_id);
        $algorithm = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);

        return $this->encryptionUtil->encode($token, $private_key, $algorithm);
    }

    /**
     * @param $userInfo
     * @return array
     * @throws LogicException
     */
    private function getUserIdAndAuthTime($userInfo)
    {
        $auth_time = null;

        // support an array for user_id / auth_time
        if (is_array($userInfo)) {
            if (!isset($userInfo['user_id'])) {
                throw new LogicException('if $user_id argument is an array, user_id index must be set');
            }

            $auth_time = isset($userInfo['auth_time']) ? $userInfo['auth_time'] : null;
            $user_id = $userInfo['user_id'];
        } else {
            $user_id = $userInfo;
        }

        if (is_null($auth_time)) {
            $auth_time = time();
        }

        // userInfo is a scalar, and so this is the $user_id. Auth Time is null
        return array($user_id, $auth_time);
    }
}
