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
    int nummber;
};

int handle_auth(ssh_session session);
int log_con1_mysql(struct connection *c);

#endif
