
DROP TABLE IF EXISTS `refresh_token_table`;

CREATE TABLE `refresh_token_table` (
  `id_refresh_token` mediumint(128) unsigned NOT NULL AUTO_INCREMENT,
  `expires` int(12) unsigned NOT NULL DEFAULT '0',
  `client_id` mediumint(128) unsigned NOT NULL DEFAULT '0',
  `user_id` int(13) unsigned NOT NULL DEFAULT '0',
  `refresh_token` varchar(255) unsigned NOT NULL DEFAULT '',
  `scope` tinytext
  PRIMARY KEY (`id_refresh_token`),
  KEY `SEARCH` (`user_id`,`client_id`,`expires`,`refresh_token`(16))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
