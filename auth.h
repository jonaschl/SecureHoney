#ifndef AUTH_H

#define AUTH_H
#include <libssh/libssh.h>
// for UINT64
#include <stdint.h>
#define MAXBUF 100

struct connection {
    ssh_session session;
    ssh_message message;
    char client_ip[MAXBUF];
    char con_time[MAXBUF];
    const char *user;
    const char *pass;
    const char *banner;
    const char *cipher_out;
    const char *cipher_in;
    int protocol_version;
    int openssh_version;
    uint64_t session_id;
    uint64_t id;
    int number;
};

int handle_auth(ssh_session session, uint64_t new_session_id);
int log_con1_mysql(struct connection *c);
int log_con2_mysql(struct connection *c);
int log_con_end_mysql(struct connection *c);
int log_attempt_mysql(struct connection *c, const char *username, const char* password);
int log_command_mysql(struct connection *c, char* command);
int get_first_session_id_mysql(uint64_t *firstid);

#endif
