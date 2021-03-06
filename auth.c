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

// for json
#include <jansson.h>


/* Stores the current UTC time. Returns 0 on error. */
static int get_utc(struct connection *c) {
    time_t t;
    t = time(NULL);
    return strftime(c->con_time, MAXBUF, "%Y-%m-%d %H:%M:%S", gmtime(&t));
}
// For the auth_password() function
// return 1 (true) when authenticated 0 (false) when not authenticated
// case:  1 return everytime 0 (authentication is not possible)
//        2 return everytime 1 (authenticated with very password and every username)
//        3 return 1 when password = the PASSWORD and username = USERNAME
static int auth_password(const char *user, const char *password){
    #if (AUTHENTICATION == 1)
    // not authenticated
    return 0;
    #endif
    #if (AUTHENTICATION == 2)
    //authenticated
    return 1;
    #endif
    #if (AUTHENTICATION == 3)
    if(strcmp(user, USERNAME))
    return 0; // not authenticated
    if(strcmp(password, PASSWORD))
    return 0; // not authenticated
    return 1; // authenticated
    #endif
}

/* Stores the client's IP address in the connection sruct. */
static int *get_client_ip(struct connection *c) {
    struct sockaddr_storage tmp;
    struct sockaddr_in *sock;
    unsigned int len = MAXBUF;
    getpeername(ssh_get_fd(c->session), (struct sockaddr*)&tmp, &len);
    sock = (struct sockaddr_in *)&tmp;
    inet_ntop(AF_INET, &sock->sin_addr, c->client_ip, len);
    return 0;
}


/* Write interesting information about a connection attempt to  LOGFILE.
* Returns -1 on error. */
static int log_attempt_file(struct connection *c, const char *username, const char* password) {

    FILE *f;
    int r;

    if ((f = fopen(LOGFILE, "a+")) == NULL) {
        fprintf(stderr, "Unable to open %s\n", LOGFILE);
        fclose(f);
        return -1;
    }

    if (get_utc(c) <= 0) {
        fprintf(stderr, "Error getting time\n");
        fclose(f);
        return -1;
    }

    if (get_client_ip(c) < 0) {
        fprintf(stderr, "Error getting client ip\n");
        fclose(f);
        return -1;
    }



    // get client banner cipher in and cipher out

    c->banner = ssh_get_clientbanner(c->session);
	  c->cipher_out = ssh_get_cipher_out(c->session);
	  c->cipher_in = ssh_get_cipher_in(c->session);

    // get protocol-version
    c->protocol_version = ssh_get_version(c->session);
    //create new json object
    json_t *c_json = json_object();
    //add all informatinen to the json object
    json_object_set_new(c_json, "time", json_string(c->con_time));
	  json_object_set_new(c_json, "ip-adress", json_string(c->client_ip));
	  json_object_set_new(c_json, "username", json_string(username));
	  json_object_set_new(c_json, "password", json_string(password));
	  json_object_set_new(c_json, "banner", json_string(c->banner));
	  json_object_set_new(c_json, "cipher_in", json_string(c->cipher_in));
	  json_object_set_new(c_json, "cipher_out", json_string(c->cipher_out));
    json_object_set_new(c_json, "type", json_string("login-attempt"));
    json_object_set_new(c_json, "protocol-version", json_integer(c->protocol_version));
    json_object_set_new(c_json, "openssh-version", json_integer(c->openssh_version));




    char *buffer;
    buffer = json_dumps(c_json, 0);
    if (DEBUG) { printf("%s\n", buffer); }
    r = fprintf(f, "%s\n", buffer);
    fclose(f);
    // free the json object
	  json_decref(c_json);
    free(buffer);
    return r;
}


// Write all commands into  a logfile
static int log_command_file(struct connection *c, char* command) {

      FILE *f;
      int r;

      if ((f = fopen(LOGFILE, "a+")) == NULL) {
          fprintf(stderr, "Unable to open %s\n", LOGFILE);
          fclose(f);
          return -1;
      }

      if (get_utc(c) <= 0) {
          fprintf(stderr, "Error getting time\n");
          fclose(f);
          return -1;
      }

      if (get_client_ip(c) < 0) {
          fprintf(stderr, "Error getting client ip\n");
          fclose(f);
          return -1;
      }

      //create new json object
      json_t *c_json = json_object();
      //add all informatinen to the json object
      json_object_set_new(c_json, "time", json_string(c->con_time));
  	  json_object_set_new(c_json, "ip-adress", json_string(c->client_ip));
      json_object_set_new(c_json, "command", json_string(command));
      json_object_set_new(c_json, "type", json_string("command"));





      char *buffer;
      buffer = json_dumps(c_json, 0);
      if (DEBUG) { printf("%s\n", buffer); }
      r = fprintf(f, "%s\n", buffer);
      fclose(f);
      // free the json object
  	  json_decref(c_json);
      free(buffer);
      return r;
  }

static int authenticate(ssh_session session, struct connection *c) {

    int authentication_attempts = 1;
    ssh_message message;

    while (ssh_get_status(session) != SSH_CLOSED || ssh_get_status(session) != SSH_CLOSED_ERROR){
        message=ssh_message_get(session);
        if(!message){
         printf("Failed to get the message from the ssh session");
         //not authenticated
         return 0;
        }
        switch(ssh_message_type(message)){
            case SSH_REQUEST_AUTH:
            switch(ssh_message_subtype(message)){
                case SSH_AUTH_METHOD_PASSWORD:
                // print the password and username that we get from the session
                printf("User %s wants to auth with pass %s\n", ssh_message_auth_user(message), ssh_message_auth_password(message));
                // log the login attempt to a file
                log_attempt_file(c, ssh_message_auth_user(message), ssh_message_auth_password(message));
                //log the login attempt to mysql
                log_attempt_mysql(c, ssh_message_auth_user(message), ssh_message_auth_password(message));
                // check if we get the correct password and username
                if( 1 == auth_password(ssh_message_auth_user(message), ssh_message_auth_password(message))){
                    // session is authenticated
                    ssh_message_auth_reply_success(message,0);
                    ssh_message_free(message);
                    return 1;
                }
                //check if we have reached the number of allowed authentication attempts
                if (authentication_attempts == AUTHENTICATION_ATTEMPTS){
                  ssh_message_free(message);
                  // session is not authenticated because the maximal number of authentication attempts is reached
                  return 2;
                }
                // session is not authenticated, send default message
                ssh_message_auth_set_methods(message,
                SSH_AUTH_METHOD_PASSWORD |
                SSH_AUTH_METHOD_INTERACTIVE);
                ssh_message_reply_default(message);
                // one password authenticateion attempt is done
                authentication_attempts++;
                break;

                case SSH_AUTH_METHOD_NONE:
                default:
                printf("User %s wants to auth with unknown auth %d\n", ssh_message_auth_user(message), ssh_message_subtype(message));
                ssh_message_auth_set_methods(message,
                SSH_AUTH_METHOD_PASSWORD |
                SSH_AUTH_METHOD_INTERACTIVE);
                ssh_message_reply_default(message);
                break;
            }
            break;
            // we did not get a AUTH REQUEST
            default:
            ssh_message_auth_set_methods(message,
            SSH_AUTH_METHOD_PASSWORD |
            SSH_AUTH_METHOD_INTERACTIVE);
            ssh_message_reply_default(message);
            break;
        }
        ssh_message_free(message);
    }
    return 0;
}

int Readline(ssh_channel chan, void *vptr, int maxlen) {

    int n, rc,ctr;
    char    c, c1, c2, *buffer, *buf2;
    buffer = vptr;

    for ( n = 1; n < maxlen; n++ ) {
        if ( (rc = ssh_channel_read(chan, &c, 1, 0)) == 1 ) {

            if(ctr > 0){
                ctr = ctr +1;
            }
            if(ctr > 3){
                ctr = 0;
                c1=NULL;
                c2=NULL;
            }

            if ( c == '\r' || c == '\n' ){
                printf("got a new line.\n");
                ssh_channel_write(chan,"\r\n[test@oracle ~]$ ",19);
                break;
                } else if(c == '\x1B'){
                c1 = '\x1B';
                ctr = 1;
                } else if (c1 == '\x1B' && c == '\x5B' ) {
                c2 = '\x5B';
                } else if (c1 == '\x1B' && c2 == '\x5B' && c == '\x41') {
                printf("got up\n");
                } else if (c1 == '\x1B' && c2 == '\x5B' && c == '\x42') {
                printf("got down\n");
                } else if (c1 == '\x1B' && c2 == '\x5B' && c == '\x43') {
                printf("got right\n");
                } else if (c1 == '\x1B' && c2 == '\x5B' && c == '\x44') {
                printf("got left\n");
                } else if( c == '\x03'){
                printf("ctrl+c received\n");
                ssh_channel_write(chan,"\r\n[test@oracle ~]$ ",19);
                break;
                } else if (c == '\x08') {
                printf("backspace received\n");
                break;
                } else {
                ssh_channel_write(chan, &c, 1);
            }
            if(c != '\r' || c != '\n' || c != '\0'){
                *buffer++ = c;
            }
            if ( c == '\r' ){
                break;
            }
        }
        else if ( rc == 0 ) {
            if ( n == 1 )
            return 0;
            else
            break;
        }
        else {
            if ( errno == EINTR )
            continue;
            return -1;
        }
    }
    *buffer = 0;

    return n;
}

/* Logs password auth attempts. Always replies with SSH_MESSAGE_USERAUTH_FAILURE. */
int handle_auth(ssh_session session, uint64_t new_session_id) {

    struct connection con;
    con.session = session;
    con.openssh_version = ssh_get_openssh_version(session);
    con.protocol_version = ssh_get_version(session);
    con.number = 0;
    con.session_id = new_session_id;
    log_con1_mysql(&con);
    printf("ssh version: %d\n",ssh_get_version(session));
    printf("openssh version: %d\n", ssh_get_openssh_version(session));
    /* Perform key exchange. */
    if (ssh_handle_key_exchange(con.session)) {
        fprintf(stderr, "Error exchanging keys: `%s'.\n", ssh_get_error(con.session));
        ssh_disconnect(session);
        // log the connection end time
        log_con_end_mysql(&con);
        // ssh cleanup
        ssh_finalize();
        return -1;
    }
    if (DEBUG) { printf("Successful key exchange.\n"); }

    /* Wait for a message, which should be an authentication attempt. Send the default
    * reply if it isn't. Log the attempt and quit. */
    ssh_message message;
    ssh_channel chan=0;
    char buf[2048];
    char buff2[2048];
    int auth=0;
    int shell=0;
    int i;

    log_con2_mysql(&con);

    /* proceed to authentication */
    auth = authenticate(session, &con);
    switch (auth) {
      case 0:
      printf("Authentication error: %s\n", ssh_get_error(session));
      ssh_disconnect(session);
      // log the connection end time
      log_con_end_mysql(&con);
      // ssh cleanup
      ssh_finalize();
      return 1;
      break;
      case 1:
      printf("Session successful authenticated\n");
      break;
      case 2:
      printf("Maximal number of authentication attempts reached\nExiting\n");
      ssh_disconnect(session);
      // log the connection end time
      log_con_end_mysql(&con);
      // ssh cleanup
      ssh_finalize();
      return 1;
      break;
    }
    /* wait for a channel session */
    do {
        message = ssh_message_get(session);
        if(message){
            if(ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
                chan = ssh_message_channel_request_open_reply_accept(message);
                ssh_message_free(message);
                break;
            } else {
                ssh_message_reply_default(message);
                ssh_message_free(message);
            }
        } else {
            break;
        }
    } while(!chan);

    if(!chan) {
        printf("Error: client did not ask for a channel session (%s)\n",
        ssh_get_error(session));
        ssh_disconnect(session);
        // log the connection end time
        log_con_end_mysql(&con);
        // ssh cleanup
        ssh_finalize();
        return 1;
    }

    /* wait for a shell */
    do {
        message = ssh_message_get(session);
        if(message != NULL) {
            if(ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
                if(ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
                    shell = 1;
                    ssh_message_channel_request_reply_success(message);
                    ssh_message_free(message);
                    break;
                    } else if(ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY) {
                    ssh_message_channel_request_reply_success(message);
                    ssh_message_free(message);
                    continue;
                }
            }
            ssh_message_reply_default(message);
            ssh_message_free(message);
            } else {
            break;
        }
    } while(!shell);

    if(!shell) {
        printf("Error: No shell requested (%s)\n", ssh_get_error(session));
        ssh_disconnect(session);
        // log the connection end time
        log_con_end_mysql(&con);
        // ssh cleanup
        ssh_finalize();
        return 1;
    }


    ssh_channel_write(chan, "Welcome to SSH\r\n\r\n[test@oracle ~]$ ", 35);

    while((i = Readline(chan, buff2, 1024)) > 0){

        printf("Received: (%d chars) %s\n",i-1,buff2);

        char buf[i];
        snprintf(buf, sizeof buf, "%s", buff2);
        log_command_file(&con, buf);
        //log command mysq
        log_command_mysql(&con, buf);
        if(strstr(buff2,"wget") != NULL){
            printf("This is the url to get: %.*s\n", sizeof(buff2)-5, buff2 + 5);
        }

        if(strstr(buff2,"exit")){
            printf("got exit.\n");
            ssh_disconnect(session);
            // log the connection end time
            log_con_end_mysql(&con);
            // ssh cleanup
            ssh_finalize();
            return 0;
        }

        memset(&buff2, 0, sizeof(buff2));
    }

    ssh_disconnect(session);
    // log the connection end time
    log_con_end_mysql(&con);
    // ssh cleanup
    ssh_finalize();

    if (DEBUG) { printf("Exiting child.\n"); }
    return 0;


}
