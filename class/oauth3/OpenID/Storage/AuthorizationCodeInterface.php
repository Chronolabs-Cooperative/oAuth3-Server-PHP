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


namespace OAuth3\OpenID\Storage;

use OAuth3\Storage\AuthorizationCodeInterface as BaseAuthorizationCodeInterface;
/**
 * Implement this interface to specify where the OAuth3 Server
 * should get/save authorization codes for the "Authorization Code"
 * grant type
 *
 * @author Brent Shaffer <bshafs@gmail.com>
 */
interface AuthorizationCodeInterface extends BaseAuthorizationCodeInterface
{
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
     * @param string $code         - authorization code to be stored.
     * @param mixed $client_id     - client identifier to be stored.
     * @param mixed $user_id       - user identifier to be stored.
     * @param string $redirect_uri - redirect URI(s) to be stored in a space-separated string.
     * @param int    $expires      - expiration to be stored as a Unix timestamp.
     * @param string $scope        - OPTIONAL scopes to be stored in space-separated string.
     * @param string $id_token     - OPTIONAL the OpenID Connect id_token.
     *
     * @ingroup OAuth3_section_4
     */
    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null);
}
