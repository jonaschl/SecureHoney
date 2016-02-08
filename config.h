#ifndef CONFIG_H
#define CONFIG_H

#define LISTENADDRESS   "0.0.0.0"
#define DEFAULTPORT     2222
#define RSA_KEYFILE     "/opt/securehoney/keys/honeykey"
#define LOGFILE         "/opt/securehoney/logs/text.log"
#define DEBUG           1

#define AUTHENTICATION  2
// USERNAME and PASSWORD are ignored when AUTHENTICATION = 1 or AUTHENTICATION = 2
#define USERNAME        "root"
#define PASSWORD        123456

// MYSQL Connection database
#define MYSQL_HOST  "192.168.103.125"
#define MYSQL_USER  "honeyssh"
#define MYSQL_PWD   "password"


#endif
