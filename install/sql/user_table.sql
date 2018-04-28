
DROP TABLE IF EXISTS `user_table`;

CREATE TABLE `user_table` (
  `user_id` int(13) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(32) NOT NULL DEFAULT '',
  `password` varchar(128) NOT NULL DEFAULT '',
  `scope` tinytext,
  `created` int(13) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`user_id`),
  KEY `SEARCH` (`username`(10),`password`(16))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

