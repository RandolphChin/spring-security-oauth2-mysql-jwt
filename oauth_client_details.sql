/*
Navicat MySQL Data Transfer

Source Server         : local
Source Server Version : 50723
Source Host           : localhost:3306
Source Database       : auth

Target Server Type    : MYSQL
Target Server Version : 50723
File Encoding         : 65001

Date: 2019-10-24 15:31:39
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for oauth_client_details
-- ----------------------------
DROP TABLE IF EXISTS `oauth_client_details`;
CREATE TABLE `oauth_client_details` (
  `client_id` varchar(256) NOT NULL,
  `resource_ids` varchar(256) DEFAULT NULL,
  `client_secret` varchar(256) DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL,
  `authorized_grant_types` varchar(256) DEFAULT NULL,
  `web_server_redirect_uri` varchar(256) DEFAULT NULL,
  `authorities` varchar(256) DEFAULT NULL,
  `access_token_validity` int(11) DEFAULT NULL,
  `refresh_token_validity` int(11) DEFAULT NULL,
  `additional_information` varchar(4096) DEFAULT NULL,
  `autoapprove` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of oauth_client_details
-- ----------------------------

INSERT INTO `oauth_client_details` VALUES ('clientOne', '', '$2a$10$CP09LP7yMA6E0kvjeYTSue7MaftiVeAJHH4ZwfLshrJD9fux1mWAO', 'all', 'authorization_code,refresh_token', 'http://localhost:8081/clientOne/login', null, '60', '60', null, 'true');
INSERT INTO `oauth_client_details` VALUES ('clientTwo', '', '$2a$10$sXDQlRTo6RHNZVUS0XXBTe2kX9RBTCJesb49JzadFXziOAJ1GnkXO', 'all', 'authorization_code,refresh_token', 'http://localhost:8082/clientTwo/login', '', '60', '60', '{\"site\":\"henan\"}', 'true');
INSERT INTO `oauth_client_details` VALUES ('oauth2', 'resourceOne', '$2a$10$Cf.ui70XRGI.xUDM24xuLOCH0n/Xz7s6hsL1U0DSjpets913KTym.', 'all', 'authorization_code,refresh_token', 'http://example.com', '', '7200', null, null, '');