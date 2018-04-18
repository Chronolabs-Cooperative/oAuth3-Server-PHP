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

/**
 * Implement this interface to specify where the OAuth3 Server
 * should retrieve user claims for the OpenID Connect id_token.
 */
interface UserClaimsInterface
{
    // valid scope values to pass into the user claims API call
    const VALID_CLAIMS = 'profile email address phone';

    // fields returned for the claims above
    const PROFILE_CLAIM_VALUES  = 'name family_name given_name middle_name nickname preferred_username profile picture website gender birthdate zoneinfo locale updated_at';
    const EMAIL_CLAIM_VALUES    = 'email email_verified';
    const ADDRESS_CLAIM_VALUES  = 'formatted street_address locality region postal_code country';
    const PHONE_CLAIM_VALUES    = 'phone_number phone_number_verified';

    /**
     * Return claims about the provided user id.
     *
     * Groups of claims are returned based on the requested scopes. No group
     * is required, and no claim is required.
     *
     * @param mixed  $user_id - The id of the user for which claims should be returned.
     * @param string $scope   - The requested scope.
     * Scopes with matching claims: profile, email, address, phone.
     *
     * @return array - An array in the claim => value format.
     *
     * @see http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
     */
    public function getUserClaims($user_id, $scope);
}
