DROP TABLE IF EXISTS `client_table`;

CREATE TABLE `client_table` (
  `client_id` mediumint(128) unsigned NOT NULL AUTO_INCREMENT,
  `redirect_uri` varchar(300) NOT NULL DEFAULT '',
  `grant_type` varchar(32) NOT NULL DEFAULT '',
  `user_id` int(13) unsigned NOT NULL DEFAULT '0',
  `scope` tinytext
  PRIMARY KEY (`client_id`),
  KEY `SEARCH` (`user_id`,`grant_type`(8),`redirect_uri`(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
