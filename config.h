#ifndef CONFIG_H
#define CONFIG_H

#define LISTENADDRESS   "0.0.0.0"
#define DEFAULTPORT     2222
#define RSA_KEYFILE     "/opt/securehoney/keys/honeykey"
#define LOGFILE         "/opt/securehoney/logs/text.log"
#define DEBUG           1
// sensor-id = a value which make it possible to assign the logs to a specific sensor
#define SENSOR_ID "Albus"

// 1: authentication is unpossible 2: client is authenticated with every user name and password §. client is authenticated with username and password below
#define AUTHENTICATION  authmode
// USERNAME and PASSWORD are ignored when AUTHENTICATION = 1 or AUTHENTICATION = 2
#define USERNAME        "root"
#define PASSWORD        "123456"

// MYSQL Connection database
#define MYSQL_HOST  "mysqlhost"
#define MYSQL_USER  "honeyssh"
#define MYSQL_PWD   "mysqlpassword"

// how long should the program wait before the first database query is executed
#define SLEEP_TIME sleeptime


#endif
