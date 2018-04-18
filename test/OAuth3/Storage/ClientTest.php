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

class ClientTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testGetClientDetails(ClientInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // nonexistant client_id
        $details = $storage->getClientDetails('fakeclient');
        $this->assertFalse($details);

        // valid client_id
        $details = $storage->getClientDetails('oauth_test_client');
        $this->assertNotNull($details);
        $this->assertArrayHasKey('client_id', $details);
        $this->assertArrayHasKey('client_secret', $details);
        $this->assertArrayHasKey('redirect_uri', $details);
    }

    /** @dataProvider provideStorage */
    public function testCheckRestrictedGrantType(ClientInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // Check invalid
        $pass = $storage->checkRestrictedGrantType('oauth_test_client', 'authorization_code');
        $this->assertFalse($pass);

        // Check valid
        $pass = $storage->checkRestrictedGrantType('oauth_test_client', 'implicit');
        $this->assertTrue($pass);
    }

    /** @dataProvider provideStorage */
    public function testGetAccessToken(ClientInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // nonexistant client_id
        $details = $storage->getAccessToken('faketoken');
        $this->assertFalse($details);

        // valid client_id
        $details = $storage->getAccessToken('testtoken');
        $this->assertNotNull($details);
    }

    /** @dataProvider provideStorage */
    public function testIsPublicClient(ClientInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        $publicClientId = 'public-client-'.rand();
        $confidentialClientId = 'confidential-client-'.rand();

        // create a new client
        $success1 = $storage->setClientDetails($publicClientId, '');
        $success2 = $storage->setClientDetails($confidentialClientId, 'some-secret');
        $this->assertTrue($success1);
        $this->assertTrue($success2);

        // assert isPublicClient for both
        $this->assertTrue($storage->isPublicClient($publicClientId));
        $this->assertFalse($storage->isPublicClient($confidentialClientId));
    }

    /** @dataProvider provideStorage */
    public function testSaveClient(ClientInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        $clientId = 'some-client-'.rand();

        // create a new client
        $success = $storage->setClientDetails($clientId, 'somesecret', 'http://test.com', 'client_credentials', 'clientscope1', 'brent@brentertainment.com');
        $this->assertTrue($success);

        // valid client_id
        $details = $storage->getClientDetails($clientId);
        $this->assertEquals($details['client_secret'], 'somesecret');
        $this->assertEquals($details['redirect_uri'], 'http://test.com');
        $this->assertEquals($details['grant_types'], 'client_credentials');
        $this->assertEquals($details['scope'], 'clientscope1');
        $this->assertEquals($details['user_id'], 'brent@brentertainment.com');
    }
}
