#ifndef PC_2020B_8_DOH_H
#define PC_2020B_8_DOH_H

#include "buffer.h"
#include "selector.h"
#include "base64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>



#define DOH_ATTACH(key) ( (struct DoH *)(key)->data)

struct DoH {
    // buffer
    uint8_t raw_buff[MAX_BUFF_SIZE];
    buffer buff;

    // file descriptors
    int doh_fd;
    int client_fd;

    //datos del servidor
    char *host;
    char *ip;
    size_t port;
    char *path;
    char *query;

    // fqdn para consultar
    char *fqdn;

    // respuesta de la consulta
    struct addrinfo *origin_resolution;
};

int create_doh_request(fd_selector s, char *fqdn, struct addrinfo *origin_resolution, int client_fd);

size_t b64_encoded_size(size_t inlen);

char *b64_encode(const char *in, size_t len);

char *dns_query_generator (char *fqdn, int type);

/*--------------------------------- QUERY DNS OVER HTTP ----------------------------------------------*/

uint8_t * http_query_generator(char * fqdn, char * doh_host, char * doh_path, char * doh_query, int type);

int doh_request_marshal(struct DoH *doh, int type);

#endif //PC_2020B_8_DOH_H
