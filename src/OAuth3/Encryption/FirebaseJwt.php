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


namespace OAuth3\Encryption;

/**
 * Bridge file to use the firebase/php-jwt package for JWT encoding and decoding.
 * @author Francis Chuang <francis.chuang@gmail.com>
 */
class FirebaseJwt implements EncryptionInterface
{
    public function __construct()
    {
        if (!class_exists('\JWT')) {
            throw new \ErrorException('firebase/php-jwt must be installed to use this feature. You can do this by running "composer require firebase/php-jwt"');
        }
    }

    public function encode($payload, $key, $alg = 'HS256', $keyId = null)
    {
        return \JWT::encode($payload, $key, $alg, $keyId);
    }

    public function decode($jwt, $key = null, $allowedAlgorithms = null)
    {
        try {

            //Maintain BC: Do not verify if no algorithms are passed in.
            if (!$allowedAlgorithms) {
                $key = null;
            }

            return (array)\JWT::decode($jwt, $key, $allowedAlgorithms);
        } catch (\Exception $e) {
            return false;
        }
    }

    public function urlSafeB64Encode($data)
    {
        return \JWT::urlsafeB64Encode($data);
    }

    public function urlSafeB64Decode($b64)
    {
        return \JWT::urlsafeB64Decode($b64);
    }
}
