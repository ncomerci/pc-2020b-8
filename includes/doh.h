#ifndef PC_2020B_8_DOH_H
#define PC_2020B_8_DOH_H

#include "buffer.h"
#include "selector.h"
#include "doh_response.h"
#include "base64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>


#define IPV4_LEN 4
#define IPV6_LEN 16

#define DOH_ATTACH(key) ( (struct DoH *)(key)->data)

struct addr_resolv {
    struct sockaddr_storage *origin_addr_res;
    size_t cant_addr;
};

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
    size_t req_length;

    // respuesta de la consulta
    struct addr_resolv *ar;
};

typedef enum ip_type {
    IPv4 = 0, IPv6,
}ip_type;

int create_doh_request(fd_selector s, char *fqdn, int client_fd, struct addr_resolv * ar);

size_t b64_encoded_size(size_t inlen);

char *b64_encode(const char *in, size_t len);

char *dns_query_generator(char *fqdn, ip_type type, size_t *req_length);

/*--------------------------------- QUERY DNS OVER HTTP ----------------------------------------------*/

uint8_t * http_query_generator(struct DoH *doh, ip_type type);

int doh_request_marshal(struct DoH *doh, ip_type type);

#endif //PC_2020B_8_DOH_H
