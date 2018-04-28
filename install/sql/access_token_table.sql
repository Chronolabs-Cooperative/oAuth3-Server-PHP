
DROP TABLE IF EXISTS `access_token_table`;

CREATE TABLE `access_token_table` (
  `id_access_token` mediumint(128) unsigned NOT NULL AUTO_INCREMENT,
  `expires` int(12) unsigned NOT NULL DEFAULT '0',
  `client_id` mediumint(128) unsigned NOT NULL DEFAULT '0',
  `user_id` int(13) unsigned NOT NULL DEFAULT '0',
  `scope` tinytext,
  `id_token` varchar(255) unsigned NOT NULL DEFAULT '',
  PRIMARY KEY (`id_access_token`),
  KEY `SEARCH` (`expires`,`client_id`,`user_id`,`id_token`(16))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
