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

/**
 * @author Brent Shaffer <bshafs@gmail.com>
 */
interface AccessTokenInterface extends ResponseTypeInterface
{
    /**
     * Handle the creation of access token, also issue refresh token if supported / desirable.
     *
     * @param mixed  $client_id           - client identifier related to the access token.
     * @param mixed  $user_id             - user ID associated with the access token
     * @param string $scope               - OPTONAL scopes to be stored in space-separated string.
     * @param bool   $includeRefreshToken - if true, a new refresh_token will be added to the response
     *
     * @see http://tools.ietf.org/html/rfc6749#section-5
     * @ingroup OAuth3_section_5
     */
    public function createAccessToken($client_id, $user_id, $scope = null, $includeRefreshToken = true);

    /**
     * Handle the revoking of refresh tokens, and access tokens if supported / desirable
     *
     * @param $token
     * @param $tokenTypeHint
     * @return mixed
     *
     * @todo v2.0 include this method in interface. Omitted to maintain BC in v1.x
     */
    //public function revokeToken($token, $tokenTypeHint);
}