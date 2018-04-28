DROP TABLE IF EXISTS `key_table`;

CREATE TABLE `key_table` (
  `id_key` mediumint(255) unsigned NOT NULL AUTO_INCREMENT,
  `client_id` mediumint(128) unsigned NOT NULL DEFAULT '0',
  `user_id` int(13) unsigned NOT NULL DEFAULT '0',
  `public` tinytext,
  `private` tinytext,
  `algorithm` varchar(32) NOT NULL DEFAULT '',
  `scope` tinytext
  PRIMARY KEY (`id_key`),
  KEY `SEARCH` (`client_id`,`user_id`,`algorithm`(16))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
