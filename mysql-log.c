#include "auth.h"
#include "config.h"
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pty.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pty.h>
// mysql
#include <mysql.h>
#include <my_global.h>
// for UINT64_MAX
#include <stdint.h>

// log_con1_mysql:
// log every connection with session-id, ip, start time, protocol-version, openssh-version
// log_con_end_mysql:
// log set the end time for every connection
// log_attempt_mysql:
// log every attempt with session-id, number, user,password, time
// log_command_mysql
// log every command we received with sessio-id, number, command, time

//helper functions

// get the ip
static int *get_client_ip(struct connection *c) {
    struct sockaddr_storage tmp;
    struct sockaddr_in *sock;
    unsigned int len = MAXBUF;
    getpeername(ssh_get_fd(c->session), (struct sockaddr*)&tmp, &len);
    sock = (struct sockaddr_in *)&tmp;
    inet_ntop(AF_INET, &sock->sin_addr, c->client_ip, len);
    return 0;
}
// get time

static int get_utc(struct connection *c) {
    time_t t;
    t = time(NULL);
    return strftime(c->con_time, MAXBUF, "%Y-%m-%d %H:%M:%S", gmtime(&t));
}

// escpae strings for MYSQL

int escape(char const *from, char **to, MYSQL *con){
  unsigned long length;
  int to_length;
  length = strlen(from);
  to_length = length*2+1;
  *to = malloc(sizeof(char)*to_length);
  mysql_real_escape_string(con, *to, from, length);
  return 0;
}

// log_con_mysql
int log_con1_mysql(struct connection *c){

    // get the time
    if (get_utc(c) <= 0) {
        fprintf(stderr, "Error getting time\n");
        return -1;
    }
    // get the client ip
    if (get_client_ip(c) < 0) {
        fprintf(stderr, "Error getting client ip\n");
        return -1;
    }

    //open the mysql connection
    MYSQL *mysql_con = mysql_init(NULL);

    if (mysql_con == NULL){
        fprintf(stderr, "%s\n", mysql_error(mysql_con));
        return -1;
    }

    if (mysql_real_connect(mysql_con, MYSQL_HOST, MYSQL_USER, MYSQL_PWD, NULL, MYSQL_PORT, NULL, 0) == NULL){
        fprintf(stderr, "%s\n", mysql_error(mysql_con));
        mysql_close(mysql_con);
        return -1;
    }

    char *con_time_escaped;
    escape(c->con_time, &con_time_escaped, mysql_con);

    char *client_ip_escaped;
    escape(c->client_ip, &client_ip_escaped, mysql_con);

    char *protocol_version_escaped;
    char protocol_version_string[10] = "";
    sprintf(protocol_version_string, "%d", c->protocol_version);
    escape(protocol_version_string, &protocol_version_escaped, mysql_con);

    char *openssh_version_escaped;
    char openssh_version_string[10] ="";
    sprintf(openssh_version_string, "%d", c->openssh_version);
    escape(openssh_version_string, &openssh_version_escaped, mysql_con);

    // get the session_id
    if (mysql_query(mysql_con, "SELECT MAX(`session-id`) AS `new-session-id` FROM honeyssh.connection;")) {
    fprintf(stderr, "Query failed: %s\n", mysql_error(mysql_con));
    }
    else
    {

      MYSQL_RES *result = mysql_store_result(mysql_con);

      if (!result) {
        printf("Couldn't get results set: %s\n", mysql_error(mysql_con));
      }
      else
      {
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(result)))
          {
            char *endp;
            c->session_id = strtoull(row[0], &endp, 0) +1;
          }
      }
    mysql_free_result(result);
    }

    // declare and reserve memory for the query string
    char *mysql_query_string;
    mysql_query_string = malloc(sizeof(char) * (300 + strlen(con_time_escaped) + strlen(client_ip_escaped) + strlen(protocol_version_escaped) + strlen(openssh_version_escaped)));

    // build the query string
    sprintf(mysql_query_string, "INSERT INTO `honeyssh`.`connection` (`session-id`, `ip`, `start-time`, `end-time`, `banner`, `cipher-in`, `cipher-out`, `protocol-version`, `openssh-version`, `action`, `id`) VALUES ('%llu', '%s', '%s', '%s', 'banner', 'cipher-in', 'cipher-out', '%s', '%s', '0', 'NULL');",
    c->session_id,
    client_ip_escaped,
    con_time_escaped,
    con_time_escaped,
    protocol_version_escaped,
    openssh_version_escaped);


    // execute the query
    if (mysql_query(mysql_con, mysql_query_string)) {
      fprintf(stderr, "%s\n", mysql_error(mysql_con));
    }

    free(mysql_query_string);
    free(con_time_escaped);
    free(protocol_version_escaped);
    free(openssh_version_escaped);
    free(client_ip_escaped);

    mysql_close(mysql_con);
    return 0;

}

// log_con2_mysql

int log_con2_mysql(struct connection *c){

    //open the mysql connection
    MYSQL *mysql_con = mysql_init(NULL);

    if (mysql_con == NULL){
        fprintf(stderr, "%s\n", mysql_error(mysql_con));
        return -1;
    }

    if (mysql_real_connect(mysql_con, MYSQL_HOST, MYSQL_USER, MYSQL_PWD, NULL, MYSQL_PORT, NULL, 0) == NULL){
        fprintf(stderr, "%s\n", mysql_error(mysql_con));
        mysql_close(mysql_con);
        return -1;
    }

    // get banner, cipher-in, cipher-out

    c->banner = ssh_get_clientbanner(c->session);
	  c->cipher_out = ssh_get_cipher_out(c->session);
	  c->cipher_in = ssh_get_cipher_in(c->session);

    char *banner_escaped;
    escape(c->banner, &banner_escaped, mysql_con);

    char *cipher_in_escaped;
    escape(c->cipher_in, &cipher_in_escaped, mysql_con);

    char *cipher_out_escaped;
    escape(c->cipher_out, &cipher_out_escaped, mysql_con);

    // calculate the query string length
    char *mysql_query_string;
    mysql_query_string = malloc(sizeof(char) * (300 + strlen(banner_escaped) + strlen(cipher_in_escaped) + strlen(cipher_out_escaped)));

    sprintf(mysql_query_string, "UPDATE `honeyssh`.`connection` SET `banner` = '%s', `cipher-in` = '%s', `cipher-out` = '%s' WHERE `connection`.`session-id` = %llu;",
    banner_escaped,
    cipher_in_escaped,
    cipher_out_escaped,
    c->session_id);
    printf("%s\n", mysql_query_string);
    // execute the query
    if (mysql_query(mysql_con, mysql_query_string)) {
      fprintf(stderr, "%s\n", mysql_error(mysql_con));
    }

    free(mysql_query_string);
    free(banner_escaped);
    free(cipher_in_escaped);
    free(cipher_out_escaped);

    mysql_close(mysql_con);
    return 0;

}

int log_con_end_mysql(struct connection *c) {



  MYSQL *mysql_con = mysql_init(NULL);

  if (mysql_con == NULL){
      fprintf(stderr, "%s\n", mysql_error(mysql_con));
      return -1;
  }

  if (mysql_real_connect(mysql_con, MYSQL_HOST, MYSQL_USER, MYSQL_PWD, NULL, MYSQL_PORT, NULL, 0) == NULL){
      fprintf(stderr, "%s\n", mysql_error(mysql_con));
      mysql_close(mysql_con);
      return -1;
  }

  // get the current time
  if (get_utc(c) <= 0) {
      fprintf(stderr, "Error getting time\n");
      return -1;
  }

  char *con_time_escaped;
  escape(c->con_time, &con_time_escaped, mysql_con);

  char *mysql_query_string;
  mysql_query_string = malloc(sizeof(char) * (300 + strlen(con_time_escaped)));

  sprintf(mysql_query_string, "UPDATE `honeyssh`.`connection` SET `end-time` = '%s' WHERE `connection`.`session-id` = %llu;",
  con_time_escaped,
  c->session_id);
  // execute the query
  if (mysql_query(mysql_con, mysql_query_string)) {
    fprintf(stderr, "%s\n", mysql_error(mysql_con));
  }

  free(mysql_query_string);
  free(con_time_escaped);

  mysql_close(mysql_con);
  return 0;
}


int log_attempt_mysql(struct connection *c, const char *username, const char* password){

  // connect to the mysql server
    MYSQL *mysql_con = mysql_init(NULL);

  if (mysql_con == NULL){
      fprintf(stderr, "%s\n", mysql_error(mysql_con));
      return -1;
  }

  if (mysql_real_connect(mysql_con, MYSQL_HOST, MYSQL_USER, MYSQL_PWD, NULL, MYSQL_PORT, NULL, 0) == NULL){
      fprintf(stderr, "%s\n", mysql_error(mysql_con));
      mysql_close(mysql_con);
      return -1;
  }
  // get the current time
  if (get_utc(c) <= 0) {
    fprintf(stderr, "Error getting time\n");
    return -1;
  }

  // increment the number of attempts or commands
  c->number = c->number +1;

  // escape
  char *con_time_escaped;
  escape(c->con_time, &con_time_escaped, mysql_con);

  char *username_escaped;
  escape(username, &username_escaped, mysql_con);

  char *password_escaped;
  escape(password, &password_escaped, mysql_con);

  char *mysql_query_string;
  mysql_query_string = malloc(sizeof(char) * (300 + strlen(con_time_escaped) + strlen(username_escaped) + strlen(password_escaped)));

  sprintf(mysql_query_string, "INSERT INTO `honeyssh`.`login` (`session-id`, `number`, `time`, `user`, `password`, `action`, `id`) VALUES ('%llu', '%d', '%s', '%s', '%s', '0', NULL);",
  c->session_id,
  c->number,
  con_time_escaped,
  username_escaped,
  password_escaped);
  // execute the query
  if (mysql_query(mysql_con, mysql_query_string)) {
    fprintf(stderr, "%s\n", mysql_error(mysql_con));
  }

  free(mysql_query_string);
  free(con_time_escaped);
  free(username_escaped);
  free(password_escaped);

  mysql_close(mysql_con);

  return 0;

}

int log_command_mysql(struct connection *c, char* command){

  // connect to the mysql server
    MYSQL *mysql_con = mysql_init(NULL);

  if (mysql_con == NULL){
      fprintf(stderr, "%s\n", mysql_error(mysql_con));
      return -1;
  }

  if (mysql_real_connect(mysql_con, MYSQL_HOST, MYSQL_USER, MYSQL_PWD, NULL, MYSQL_PORT, NULL, 0) == NULL){
      fprintf(stderr, "%s\n", mysql_error(mysql_con));
      mysql_close(mysql_con);
      return -1;
  }
  // get the current time
  if (get_utc(c) <= 0) {
    fprintf(stderr, "Error getting time\n");
    return -1;
  }

  // increment the number of attempts or commands
  c->number = c->number +1;

  // escape
  char *con_time_escaped;
  escape(c->con_time, &con_time_escaped, mysql_con);

  char *command_escaped;
  escape(command, &command_escaped, mysql_con);

  char *mysql_query_string;
    mysql_query_string = malloc(sizeof(char) * (300 + strlen(con_time_escaped) + strlen(command_escaped)));
  sprintf(mysql_query_string, "INSERT INTO `honeyssh`.`command` (`session-id`, `number`, `time`, `command`, `action`, `id`) VALUES ('%llu', '%d', '%s', '%s', '0', NULL);",
  c->session_id,
  c->number,
  con_time_escaped,
  command_escaped);
  // execute the query
  if (mysql_query(mysql_con, mysql_query_string)) {
    fprintf(stderr, "%s\n", mysql_error(mysql_con));
  }

  free(mysql_query_string);
  free(con_time_escaped);
  free(command_escaped);

  mysql_close(mysql_con);

  return 0;

}
