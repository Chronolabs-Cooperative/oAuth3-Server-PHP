DROP TABLE IF EXISTS `code_table`;

CREATE TABLE `code_table` (
  `id_code` mediumint(128) unsigned NOT NULL AUTO_INCREMENT,
  `client_id` mediumint(128) unsigned NOT NULL DEFAULT '0',
  `redirect_uri` varchar(300) NOT NULL DEFAULT '',
  `expires` int(12) unsigned NOT NULL DEFAULT '0',
  `user_id` int(13) unsigned NOT NULL DEFAULT '0',
  `scope` tinytext
  PRIMARY KEY (`id_code`),
  KEY `SEARCH` (`client_id`,`user_id`,`expires`,`redirect_uri`(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
