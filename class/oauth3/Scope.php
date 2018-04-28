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


namespace OAuth3;

use InvalidArgumentException;
use OAuth3\Storage\Memory;
use OAuth3\Storage\ScopeInterface as ScopeStorageInterface;

/**
* @see ScopeInterface
*/
class Scope implements ScopeInterface
{
    protected $storage;

    /**
     * Constructor
     *
     * @param mixed $storage - Either an array of supported scopes, or an instance of OAuth3\Storage\ScopeInterface
     *
     * @throws InvalidArgumentException
     */
    public function __construct($storage = null)
    {
        if (is_null($storage) || is_array($storage)) {
            $storage = new Memory((array) $storage);
        }

        if (!$storage instanceof ScopeStorageInterface) {
            throw new InvalidArgumentException("Argument 1 to OAuth3\Scope must be null, an array, or instance of OAuth3\Storage\ScopeInterface");
        }

        $this->storage = $storage;
    }

    /**
     * Check if everything in required scope is contained in available scope.
     *
     * @param string $required_scope  - A space-separated string of scopes.
     * @param string $available_scope - A space-separated string of scopes.
     * @return bool                   - TRUE if everything in required scope is contained in available scope and FALSE
     *                                  if it isn't.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-7
     *
     * @ingroup OAuth3_section_7
     */
    public function checkScope($required_scope, $available_scope)
    {
        $required_scope = explode(' ', trim($required_scope));
        $available_scope = explode(' ', trim($available_scope));

        return (count(array_diff($required_scope, $available_scope)) == 0);
    }

    /**
     * Check if the provided scope exists in storage.
     *
     * @param string $scope - A space-separated string of scopes.
     * @return bool         - TRUE if it exists, FALSE otherwise.
     */
    public function scopeExists($scope)
    {
        // Check reserved scopes first.
        $scope = explode(' ', trim($scope));
        $reservedScope = $this->getReservedScopes();
        $nonReservedScopes = array_diff($scope, $reservedScope);
        if (count($nonReservedScopes) == 0) {
            return true;
        } else {
            // Check the storage for non-reserved scopes.
            $nonReservedScopes = implode(' ', $nonReservedScopes);

            return $this->storage->scopeExists($nonReservedScopes);
        }
    }

    /**
     * @param RequestInterface $request
     * @return string
     */
    public function getScopeFromRequest(RequestInterface $request)
    {
        // "scope" is valid if passed in either POST or QUERY
        return $request->request('scope', $request->query('scope'));
    }

    /**
     * @param null $client_id
     * @return mixed
     */
    public function getDefaultScope($client_id = null)
    {
        return $this->storage->getDefaultScope($client_id);
    }

    /**
     * Get reserved scopes needed by the server.
     *
     * In case OpenID Connect is used, these scopes must include:
     * 'openid', offline_access'.
     *
     * @return array - An array of reserved scopes.
     */
    public function getReservedScopes()
    {
        return array('openid', 'offline_access');
    }
}
