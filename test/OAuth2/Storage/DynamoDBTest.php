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

namespace OAuth2\Storage;

class DynamoDBTest extends BaseTest
{
    public function testGetDefaultScope()
    {
        $client = $this->getMockBuilder('\Aws\DynamoDb\DynamoDbClient')
            ->disableOriginalConstructor()
            ->setMethods(array('query'))
            ->getMock();

        $return = $this->getMockBuilder('\Guzzle\Service\Resource\Model')
            ->setMethods(array('count', 'toArray'))
            ->getMock();

        $data = array(
            'Items' => array(),
            'Count' => 0,
            'ScannedCount'=> 0
        );

        $return->expects($this->once())
            ->method('count')
            ->will($this->returnValue(count($data)));

        $return->expects($this->once())
            ->method('toArray')
            ->will($this->returnValue($data));

        // should return null default scope if none is set in database
        $client->expects($this->once())
            ->method('query')
            ->will($this->returnValue($return));

        $storage = new DynamoDB($client);
        $this->assertNull($storage->getDefaultScope());
    }
}
