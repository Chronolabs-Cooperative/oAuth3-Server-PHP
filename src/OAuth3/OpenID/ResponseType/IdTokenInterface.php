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

use OAuth3\ResponseType\ResponseTypeInterface;

interface IdTokenInterface extends ResponseTypeInterface
{
    /**
     * Create the id token.
     *
     * If Authorization Code Flow is used, the id_token is generated when the
     * authorization code is issued, and later returned from the token endpoint
     * together with the access_token.
     * If the Implicit Flow is used, the token and id_token are generated and
     * returned together.
     *
     * @param string $client_id        - The client id.
     * @param mixed  $userInfo         - User info
     * @param string $nonce            - OPTIONAL The nonce.
     * @param string $userClaims       - OPTIONAL Claims about the user.
     * @param string $access_token     - OPTIONAL The access token, if known.

     * @internal param string $user_id - The user id.
     * @return string The ID Token represented as a JSON Web Token (JWT).
     *
     * @see http://openid.net/specs/openid-connect-core-1_0.html#IDToken
     */
    public function createIdToken($client_id, $userInfo, $nonce = null, $userClaims = null, $access_token = null);
}
