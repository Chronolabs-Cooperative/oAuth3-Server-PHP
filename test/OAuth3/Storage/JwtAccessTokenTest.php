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

use OAuth3\Encryption\Jwt;

class JwtAccessTokenTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testSetAccessToken($storage)
    {
        if (!$storage instanceof PublicKey) {
            // incompatible storage
            return;
        }

        $crypto = new jwtAccessToken($storage);

        $publicKeyStorage = Bootstrap::getInstance()->getMemoryStorage();
        $encryptionUtil = new Jwt();

        $jwtAccessToken = array(
            'access_token' => rand(),
            'expires' => time() + 100,
            'scope'   => 'foo',
        );

        $token = $encryptionUtil->encode($jwtAccessToken, $storage->getPrivateKey(), $storage->getEncryptionAlgorithm());

        $this->assertNotNull($token);

        $tokenData = $crypto->getAccessToken($token);

        $this->assertTrue(is_array($tokenData));

        /* assert the decoded token is the same */
        $this->assertEquals($tokenData['access_token'], $jwtAccessToken['access_token']);
        $this->assertEquals($tokenData['expires'], $jwtAccessToken['expires']);
        $this->assertEquals($tokenData['scope'], $jwtAccessToken['scope']);
    }
}
