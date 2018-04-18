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

/**
 * Implement this interface to specify where the OAuth3 Server
 * should get/save authorization codes for the "Authorization Code"
 * grant type
 *
 * @author Brent Shaffer <bshafs@gmail.com>
 */
interface AuthorizationCodeInterface
{
    /**
     * The Authorization Code grant type supports a response type of "code".
     *
     * @var string
     * @see http://tools.ietf.org/html/rfc6749#section-1.4.1
     * @see http://tools.ietf.org/html/rfc6749#section-4.2
     */
    const RESPONSE_TYPE_CODE = "code";

    /**
     * Fetch authorization code data (probably the most common grant type).
     *
     * Retrieve the stored data for the given authorization code.
     *
     * Required for OAuth3::GRANT_TYPE_AUTH_CODE.
     *
     * @param $code
     * Authorization code to be check with.
     *
     * @return
     * An associative array as below, and NULL if the code is invalid
     * @code
     * return array(
     *     "client_id"    => CLIENT_ID,      // REQUIRED Stored client identifier
     *     "user_id"      => USER_ID,        // REQUIRED Stored user identifier
     *     "expires"      => EXPIRES,        // REQUIRED Stored expiration in unix timestamp
     *     "redirect_uri" => REDIRECT_URI,   // REQUIRED Stored redirect URI
     *     "scope"        => SCOPE,          // OPTIONAL Stored scope values in space-separated string
     * );
     * @endcode
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4.1
     *
     * @ingroup OAuth3_section_4
     */
    public function getAuthorizationCode($code);

    /**
     * Take the provided authorization code values and store them somewhere.
     *
     * This function should be the storage counterpart to getAuthCode().
     *
     * If storage fails for some reason, we're not currently checking for
     * any sort of success/failure, so you should bail out of the script
     * and provide a descriptive fail message.
     *
     * Required for OAuth3::GRANT_TYPE_AUTH_CODE.
     *
     * @param string $code         - Authorization code to be stored.
     * @param mixed  $client_id    - Client identifier to be stored.
     * @param mixed  $user_id      - User identifier to be stored.
     * @param string $redirect_uri - Redirect URI(s) to be stored in a space-separated string.
     * @param int    $expires      - Expiration to be stored as a Unix timestamp.
     * @param string $scope        - OPTIONAL Scopes to be stored in space-separated string.
     *
     * @ingroup OAuth3_section_4
     */
    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null);

    /**
     * once an Authorization Code is used, it must be expired
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.2
     *
     *    The client MUST NOT use the authorization code
     *    more than once.  If an authorization code is used more than
     *    once, the authorization server MUST deny the request and SHOULD
     *    revoke (when possible) all tokens previously issued based on
     *    that authorization code
     *
     */
    public function expireAuthorizationCode($code);
}
