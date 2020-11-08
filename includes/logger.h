#ifndef LOGGER_H
#define LOGGER_H
#include <sys/types.h>
#include <time.h>
#include <stdio.h>
#include <sys/socket.h>
#include "selector.h"
#include "socks5nio.h"
#include "request.h"
#include "hello.h"
#include "auth.h"
#define DATE_SIZE 21

enum protocol {
    HTTP = 0,
    POP3,
};

static const char *protocol_str[] = {"HTTP", "POP3"};

struct log_info{
    uint8_t method;
    struct usr user_info;
    enum socks_reply_status status;
    enum socks_atyp atyp;
    struct sockaddr_storage client_addr;
    union socks_addr dest_addr;
    in_port_t dest_port;

    //Sniffer
    char *user;
    char *passwd;
    enum protocol protcol;
};

void log_access(struct log_info *socks_info);
void log_sniff(struct log_info *socks_info);

#endif 