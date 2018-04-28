<?php
/**
 * Chronolabs Torrent Tracker REST API
 *
 * You may not change or alter any portion of this comment or credits
 * of supporting developers from this source code or any supporting source code
 * which is considered copyrighted (c) material of the original comment or credit authors.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * @copyright       	Chronolabs Cooperative http://snails.email
 * @license         	General Public License version 3 (http://snails.email/briefs/legal/general-public-licence/13,3.html)
 * @package         	tracker
 * @since           	2.1.9
 * @author          	Simon Roberts <wishcraft@users.sourceforge.net>
 * @subpackage		api
 * @description		Torrent Tracker REST API
 * @link				http://sourceforge.net/projects/chronolabsapis
 * @link				http://cipher.snails.email
 */

define('_API_FATAL_MESSAGE', 'Error: %s');
define('_API_FATAL_BACKTRACE', 'Error: %s<br/><br/>%s');

require_once __DIR__.'/common.php';
require_once dirname(__DIR__).'/class/cache/apicache.php';
require_once dirname(__DIR__).'/class/xcp/xcp.class.php';

if (!function_exists("loadLanguage")) {
    
    /* function loadLanguage()
     *
     * 	Get a supporting domain system for the API
     * @author 		Simon Roberts (Chronolabs) simon@labs.coop
     *
     * @return 		float()
     */
    function loadLanguage($resource = '', $default = 'english')
    {
        if (in_array("$resource.php", APILists::getFileListAsArray(dirname(__DIR__) . DS . 'language' . DS . API_LANGUAGE)))
            @include_once dirname(__DIR__) . DS . 'language' . DS . API_LANGUAGE . DS . "$resource.php";
        elseif (in_array("$resource.php", APILists::getFileListAsArray(dirname(__DIR__) . DS . 'language' . DS . $default)))
            @include_once dirname(__DIR__) . DS . 'language' . DS . $default . DS . "$resource.php";
    }
}

if (!function_exists("api_loadLanguage")) {
    
    /* function api_loadLanguage()
     *api_
     * 	Get a supporting domain system for the API
     * @author 		Simon Roberts (Chronolabs) simon@labs.coop
     *
     * @return 		float()
     */
    function api_loadLanguage($resource = '', $default = 'english')
    {
        @loadLanguage($resource, $default);
    }
}


if (!function_exists("getURIData")) {
    
    /* function getURIData()
     *
     * 	Get a supporting domain system for the API
     * @author 		Simon Roberts (Chronolabs) simon@labs.coop
     *
     * @return 		float()
     */
    function getURIData($uri = '', $timeout = 25, $connectout = 25, $post = array(), $headers = array())
    {
        if (!function_exists("curl_init"))
        {
            die("Install PHP Curl Extension ie: $ sudo apt-get install php-curl -y");
        }
        $GLOBALS['php-curl'][md5($uri)] = array();
        if (!$btt = curl_init($uri)) {
            return false;
        }
        if (count($post)==0 || empty($post))
            curl_setopt($btt, CURLOPT_POST, false);
        else {
            $uploadfile = false;
            foreach($post as $field => $value)
                if (substr($value , 0, 1) == '@' && !file_exists(substr($value , 1, strlen($value) - 1)))
                    unset($post[$field]);
                else 
                    $uploadfile = true;
            curl_setopt($btt, CURLOPT_POST, true);
            curl_setopt($btt, CURLOPT_POSTFIELDS, http_build_query($post));
            
            if (!empty($headers))
                foreach($headers as $key => $value)
                    if ($uploadfile==true && substr($value, 0, strlen('Content-Type:')) == 'Content-Type:')
                        unset($headers[$key]);
            if ($uploadfile==true)
                $headers[]  = 'Content-Type: multipart/form-data';
        }
        if (count($headers)==0 || empty($headers))
            curl_setopt($btt, CURLOPT_HEADER, false);
        else {
            curl_setopt($btt, CURLOPT_HEADER, true);
            curl_setopt($btt, CURLOPT_HTTPHEADER, $headers);
        }
        curl_setopt($btt, CURLOPT_CONNECTTIMEOUT, $connectout);
        curl_setopt($btt, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($btt, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($btt, CURLOPT_VERBOSE, false);
        curl_setopt($btt, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($btt, CURLOPT_SSL_VERIFYPEER, false);
        $data = curl_exec($btt);
        $GLOBALS['php-curl'][md5($uri)]['http']['posts'] = $post;
        $GLOBALS['php-curl'][md5($uri)]['http']['headers'] = $headers;
        $GLOBALS['php-curl'][md5($uri)]['http']['code'] = curl_getinfo($btt, CURLINFO_HTTP_CODE);
        $GLOBALS['php-curl'][md5($uri)]['header']['size'] = curl_getinfo($btt, CURLINFO_HEADER_SIZE);
        $GLOBALS['php-curl'][md5($uri)]['header']['value'] = curl_getinfo($btt, CURLINFO_HEADER_OUT);
        $GLOBALS['php-curl'][md5($uri)]['size']['download'] = curl_getinfo($btt, CURLINFO_SIZE_DOWNLOAD);
        $GLOBALS['php-curl'][md5($uri)]['size']['upload'] = curl_getinfo($btt, CURLINFO_SIZE_UPLOAD);
        $GLOBALS['php-curl'][md5($uri)]['content']['length']['download'] = curl_getinfo($btt, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
        $GLOBALS['php-curl'][md5($uri)]['content']['length']['upload'] = curl_getinfo($btt, CURLINFO_CONTENT_LENGTH_UPLOAD);
        $GLOBALS['php-curl'][md5($uri)]['content']['type'] = curl_getinfo($btt, CURLINFO_CONTENT_TYPE);
        curl_close($btt);
        return $data;
    }
}

if (!function_exists("cleanWhitespaces")) {
    /**
     *
     * @param array $array
     */
    function cleanWhitespaces($array = array())
    {
        foreach($array as $key => $value)
        {
            if (is_array($value))
                $array[$key] = cleanWhitespaces($value);
            else {
                $array[$key] = trim(str_replace(array("\n", "\r", "\t"), "", $value));
            }
        }
        return $array;
    }
}

if (!function_exists("writeRawFile")) {
    /**
     *
     * @param string $file
     * @param string $data
     */
    function writeRawFile($file = '', $data = '')
    {
        $lineBreak = "\n";
        if (substr(PHP_OS, 0, 3) == 'WIN') {
            $lineBreak = "\r\n";
        }
        if (!is_dir(dirname($file)))
            mkdir(dirname($file), 0777, true);
        if (is_file($file))
            unlink($file);
        $data = str_replace("\n", $lineBreak, $data);
        $ff = fopen($file, 'w');
        fwrite($ff, $data, strlen($data));
        fclose($ff);
    }
}

/**
 * validateMD5()
 * Validates an MD5 Checksum
 *
 * @param string $email
 * @return boolean
 */
function validateMD5($md5) {
    if(preg_match("/^[a-f0-9]{32}$/i", $md5)) {
        return true;
    } else {
        return false;
    }
}

/**
 * validateEmail()
 * Validates an Email Address
 *
 * @param string $email
 * @return boolean
 */
function validateEmail($email) {
    if(preg_match("^[_a-zA-Z0-9-]+(\.[_a-zA-Z0-9-]+)*@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.([0-9]{1,3})|([a-zA-Z]{2,3})|(aero|coop|info|mobi|asia|museum|name))$", $email)) {
        return true;
    } else {
        return false;
    }
}

/**
 * validateDomain()
 * Validates a Domain Name
 *
 * @param string $domain
 * @return boolean
 */
function validateDomain($domain) {
    if(!preg_match("/^([-a-z0-9]{2,100})\.([a-z\.]{2,8})$/i", $domain)) {
        return false;
    }
    return $domain;
}

/**
 * validateIPv4()
 * Validates and IPv6 Address
 *
 * @param string $ip
 * @return boolean
 */
function validateIPv4($ip) {
    if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE) === FALSE) // returns IP is valid
    {
        return false;
    } else {
        return true;
    }
}

/**
 * validateIPv6()
 * Validates and IPv6 Address
 *
 * @param string $ip
 * @return boolean
 */
function validateIPv6($ip) {
    if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === FALSE) // returns IP is valid
    {
        return false;
    } else {
        return true;
    }
}

function yonkhostbyname6($host, $try_a = false) {
    // get AAAA record for $host
    // if $try_a is true, if AAAA fails, it tries for A
    // the first match found is returned
    // otherwise returns false
    
    $dns = gethostbynamel6($host, $try_a);
    if ($dns == false) { return false; }
    else { return $dns[0]; }
}

function yonkhostbynamel6($host, $try_a = false) {
    // get AAAA records for $host,
    // if $try_a is true, if AAAA fails, it tries for A
    // results are returned in an array of ips found matching type
    // otherwise returns false
    
    $dns6 = dns_get_record($host, DNS_AAAA);
    if ($try_a == true) {
        $dns4 = dns_get_record($host, DNS_A);
        $dns = array_merge($dns4, $dns6);
    }
    else { $dns = $dns6; }
    $ip6 = array();
    $ip4 = array();
    foreach ($dns as $record) {
        if ($record["type"] == "A") {
            $ip4[] = $record["ip"];
        }
        if ($record["type"] == "AAAA") {
            $ip6[] = $record["ipv6"];
        }
    }
    if (count($ip6) < 1) {
        if ($try_a == true) {
            if (count($ip4) < 1) {
                return false;
            }
            else {
                return $ip4;
            }
        }
        else {
            return false;
        }
    }
    else {
        return $ip6;
    }
}


if (!function_exists("yonkBaseRealm")) {
    /**
     * Gets the base domain of a tld with subdomains, that is the root domain header for the network rout
     *
     * @param string $url
     *
     * @return string
     */
    function yonkBaseRealm($realm = '')
    {       
        
        if (!validateDomain($realm))
            return false;
            
        static $fallout, $classes;
        
        if (empty($classes))
            if (!$classes = APICache::read('internet-strata-classes'))
            {
                $classes = array_keys(json_decode(getURIData(API_STRATA_URL ."/v2/strata/json.api", 15, 10), true));
                APICache::write('internet-strata-classes', $classes, 3600 * 72);
            }
        if (empty($fallout))
            if (!$fallout = APICache::read('internet-strata-fallout'))
            {
                $fallout = array_keys(json_decode(getURIData(API_STRATA_URL ."/v2/fallout/json.api", 15, 10), true));
                APICache::write('internet-strata-fallout', $fallout, 3600 * 72);
            }
            
        // Get Full Hostname
        if (!filter_var($realm, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 || FILTER_FLAG_IPV4) === false)
            return $realm;
        
        // break up domain, reverse
        $elements = explode('.', $realm);
        $elements = array_reverse($elements);
                
        // Returns Base Domain
        if (in_array($elements[0], $classes))
            return $elements[1] . '.' . $elements[0];
        elseif (in_array($elements[0], $fallout) && in_array($elements[1], $classes))
            return $elements[2] . '.' . $elements[1] . '.' . $elements[0];
        elseif (in_array($elements[0], $fallout))
            return  $elements[1] . '.' . $elements[0];
        else
            return  $elements[1] . '.' . $elements[0];
        
        return parse_url($uri, PHP_URL_HOST);
    }
}

if (!function_exists("getURLId")) {
    /**
     * Redirect HTML Display
     *
     * @param string $uri
     * @param integer $seconds
     * @param string $message
     *
     */
    function yonkURLId($url = '')
    {
        $sql = "SELECT `id` FROM `" . $GLOBALS['APIDB']->prefix('urls') . "` WHERE `url` LIKE '" . $GLOBALS['APIDB']->escape($url) . "'";
        list($id) = $GLOBALS['APIDB']->fetchRow($GLOBALS['APIDB']->queryF($sql));
        if ($id<>0) {
            $sql = "UPDATE `" . $GLOBALS['APIDB']->prefix('urls') . "` SET `hits` = `hits` + 1 WHERE `id` = '$id'";
            $GLOBALS['APIDB']->queryF($sql);
            return $id;
        }
        
        $sql = "INSERT INTO `" . $GLOBALS['APIDB']->prefix('urls') . "` (`url`, `netbios-id`, `realm-id`, `hits`, `created`) VALUES('" . $GLOBALS['APIDB']->escape($url) . "', '" . yonkNetBiosId(parse_url($url, PHP_URL_HOST)) . "', '" . yonkRealmId(getBaseDomain(parse_url($url, PHP_URL_HOST))) . "', 1, UNIX_TIMESTAMP())";
        if (!$GLOBALS['APIDB']->queryF($sql))
            die("SQL Failed: $sql;");
        return $GLOBALS['APIDB']->getInsertId();
    }
}


if (!function_exists("getNetBiosId")) {
    /**
     * Redirect HTML Display
     *
     * @param string $uri
     * @param integer $seconds
     * @param string $message
     *
     */
    function yonkNetBiosId($netbios = '')
    {
        if (!validateDomain($netbios))
            return false;
        
        $sql = "SELECT `id` FROM `" . $GLOBALS['APIDB']->prefix('netbios') . "` WHERE `netbios` LIKE '" . $GLOBALS['APIDB']->escape($netbios) . "'";
        list($id) = $GLOBALS['APIDB']->fetchRow($GLOBALS['APIDB']->queryF($sql));
        if ($id<>0) {
            $sql = "UPDATE `" . $GLOBALS['APIDB']->prefix('netbios') . "` SET `hits` = `hits` + 1 WHERE `id` = '$id'";
            $GLOBALS['APIDB']->queryF($sql);
            return $id;
        }
        
        $ipv4 = gethostbyname($netbios);
        $ipv6 = gethostbyname6($netbios, false);
        
        $sql = "INSERT INTO `" . $GLOBALS['APIDB']->prefix('netbios') . "` (`netbios`, `ipv4-id`, `ipv6-id`, `realm-id`, `hits`, `created`) VALUES('" . $GLOBALS['APIDB']->escape($netbios) . "', '" . yonkIPv4Id($ipv4) . "', '" . yonkIPv6Id($ipv4) . "', '" . yonkRealmId(getBaseDomain($netbios)) . "', 1, UNIX_TIMESTAMP())";
        if (!$GLOBALS['APIDB']->queryF($sql))
            die("SQL Failed: $sql;");
        return $GLOBALS['APIDB']->getInsertId();
    }
}

if (!function_exists("yonkRealmId")) {
    /**
     * Redirect HTML Display
     *
     * @param string $uri
     * @param integer $seconds
     * @param string $message
     *
     */
    function yonkRealmId($realm = '')
    {
        if (!validateDomain($realm))
            return false;
            
        $sql = "SELECT `id` FROM `" . $GLOBALS['APIDB']->prefix('realms') . "` WHERE `realm` LIKE '" . $GLOBALS['APIDB']->escape($realm) . "'";
        list($id) = $GLOBALS['APIDB']->fetchRow($GLOBALS['APIDB']->queryF($sql));
        if ($id<>0) {
            $sql = "UPDATE `" . $GLOBALS['APIDB']->prefix('realms') . "` SET `hits` = `hits` + 1 WHERE `id` = '$id'";
            $GLOBALS['APIDB']->queryF($sql);
            return $id;
        }
        
        $ipv4 = gethostbyname($realm);
        $ipv6 = gethostbyname6($realm, false);
        
        $sql = "INSERT INTO `" . $GLOBALS['APIDB']->prefix('realms') . "` (`realm`, `ipv4-id`, `ipv6-id`, `realm-whois-id`, `ipv4-whois-id`, `ipv6-whois-id`, `hits`, `created`) VALUES('" . $GLOBALS['APIDB']->escape($realm) . "', '" . yonkIPv4Id($ipv4) . "', '" . yonkIPv6Id($ipv6) . "', '" . yonkWhoISId($realm) . "', '" . yonkWhoISId($ipv4) . "', '" . yonkWhoISId($ipv6) . "', 1, UNIX_TIMESTAMP())";
        if (!$GLOBALS['APIDB']->queryF($sql))
            die("SQL Failed: $sql;");
        return $GLOBALS['APIDB']->getInsertId();
    }
}

if (!function_exists("yonkIPv4Id")) {
    /**
     * Redirect HTML Display
     *
     * @param string $uri
     * @param integer $seconds
     * @param string $message
     *
     */
    function yonkIPv4Id($ipv4 = '')
    {
        if (!validateIPv4($ipv4))
            return false;
            
        $sql = "SELECT `id` FROM `" . $GLOBALS['APIDB']->prefix('ipv4') . "` WHERE `ipv4` LIKE '" . $GLOBALS['APIDB']->escape($ipv4) . "'";
        list($id) = $GLOBALS['APIDB']->fetchRow($GLOBALS['APIDB']->queryF($sql));
        if ($id<>0) {
            $sql = "UPDATE `" . $GLOBALS['APIDB']->prefix('ipv4') . "` SET `hits` = `hits` + 1 WHERE `id` = '$id'";
            $GLOBALS['APIDB']->queryF($sql);
            return $id;
        }
                    
        $sql = "INSERT INTO `" . $GLOBALS['APIDB']->prefix('ipv4') . "` (`ipv4`, `whois-id`, `hits`, `created`) VALUES('" . $GLOBALS['APIDB']->escape($ipv4) . "', '" . yonkWhoISId($ipv4) . "', 1, UNIX_TIMESTAMP())";
        if (!$GLOBALS['APIDB']->queryF($sql))
            die("SQL Failed: $sql;");
        return $GLOBALS['APIDB']->getInsertId();
    }
}


if (!function_exists("yonkIPv6Id")) {
    /**
     * Redirect HTML Display
     *
     * @param string $uri
     * @param integer $seconds
     * @param string $message
     *
     */
    function yonkIPv6Id($ipv6 = '')
    {
        if (!validateIPv6($ipv6))
            return false;
        
        $sql = "SELECT `id` FROM `" . $GLOBALS['APIDB']->prefix('ipv6') . "` WHERE `ipv6` LIKE '" . $GLOBALS['APIDB']->escape($ipv6) . "'";
        list($id) = $GLOBALS['APIDB']->fetchRow($GLOBALS['APIDB']->queryF($sql));
        if ($id<>0) {
            $sql = "UPDATE `" . $GLOBALS['APIDB']->prefix('ipv6') . "` SET `hits` = `hits` + 1 WHERE `id` = '$id'";
            $GLOBALS['APIDB']->queryF($sql);
            return $id;
        }
        
        $sql = "INSERT INTO `" . $GLOBALS['APIDB']->prefix('ipv6') . "` (`ipv6`, `whois-id`, `hits`, `created`) VALUES('" . $GLOBALS['APIDB']->escape($ipv6) . "', '" . yonkWhoISId($ipv6) . "', 1, UNIX_TIMESTAMP())";
        if (!$GLOBALS['APIDB']->queryF($sql))
            die("SQL Failed: $sql;");
        return $GLOBALS['APIDB']->getInsertId();
    }
}


if (!class_exists("XmlDomConstruct")) {
	/**
	 * class XmlDomConstruct
	 *
	 * 	Extends the DOMDocument to implement personal (utility) methods.
	 *
	 * @author 		Simon Roberts (Chronolabs) simon@snails.email
	 */
	class XmlDomConstruct extends DOMDocument {

		/**
		 * Constructs elements and texts from an array or string.
		 * The array can contain an element's name in the index part
		 * and an element's text in the value part.
		 *
		 * It can also creates an xml with the same element tagName on the same
		 * level.
		 *
		 * ex:
		 * <nodes>
		 *   <node>text</node>
		 *   <node>
		 *     <field>hello</field>
		 *     <field>world</field>
		 *   </node>
		 * </nodes>
		 *
		 * Array should then look like:
		 *
		 * Array (
		 *   "nodes" => Array (
		 *     "node" => Array (
		 *       0 => "text"
		 *       1 => Array (
		 *         "field" => Array (
		 *           0 => "hello"
		 *           1 => "world"
		 *         )
		 *       )
		 *     )
		 *   )
		 * )
		 *
		 * @param mixed $mixed An array or string.
		 *
		 * @param DOMElement[optional] $domElement Then element
		 * from where the array will be construct to.
		 *
		 * @author 		Simon Roberts (Chronolabs) simon@snails.email
		 *
		 */
		public function fromMixed($mixed, DOMElement $domElement = null) {

			$domElement = is_null($domElement) ? $this : $domElement;

			if (is_array($mixed)) {
				foreach( $mixed as $index => $mixedElement ) {

					if ( is_int($index) ) {
						if ( $index == 0 ) {
							$node = $domElement;
						} else {
							$node = $this->createElement($domElement->tagName);
							$domElement->parentNode->appendChild($node);
						}
					}

					else {
						$node = $this->createElement($index);
						$domElement->appendChild($node);
					}

					$this->fromMixed($mixedElement, $node);

				}
			} else {
				$domElement->appendChild($this->createTextNode($mixed));
			}

		}
			
	}
}

?>