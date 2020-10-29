#ifndef REQUEST_H
#define REQUEST_H
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "buffer.h"

enum request_state
{
    request_version,
    request_cmd,
    request_rsv,
    request_atyp,
    request_dest_addr,
    request_dest_addr_fqdn,
    request_dest_port,

    // done section
    request_done,

    //error section
    request_error,
    request_error_usupported_cmd,
    request_error_usupported_atyp,
    request_error_unsupported_version,
};

enum socks_cmd
{
    cmd_connect = 0x01,
    cmd_bind = 0x02,
    cmd_udp = 0x03,
};

enum socks_atyp
{
    ipv4_type = 0x01,
    domainname_type = 0x03,
    ipv6_type = 0x04,
};

union socks_addr
{
    char fqdn[0xFF];
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
};

struct request
{
    enum socks_cmd cmd;
    enum socks_atyp dest_addr_type;
    union socks_addr dest_addr;
    in_port_t dest_port;
};

typedef struct request_parser
{
    struct request *request;

    enum request_state state;
    uint8_t remaining;
    uint8_t read;
} request_parser;

enum socks_reply_status
{
    status_succeeded = 0x00,
    status_general_socks_server_failure = 0x01,
    status_connection_not_allowed_by_ruleset = 0x02,
    status_network_unreachable = 0x03,
    status_host_unreachable = 0x04,
    status_connection_refused = 0x05,
    status_ttl_expired = 0x06,
    status_command_not_supported = 0x07,
    status_address_type_not_supported = 0x08,
};

/** inicializa el parser **/
void request_parser_init(request_parser *p);

/** entrega un byte al parser. Retorna true si se llego al final **/
enum request_state request_parser_feed(request_parser *p, uint8_t b);

/** consume los bytes del mensaje del cliente y se los entrega al parser 
 * hasta que se termine de parsear 
**/
enum request_state request_consume(buffer *b, request_parser *p, bool *error);

bool request_is_done(const enum request_state state, bool *error);

void request_close(request_parser *p);

/** ensambla la respuesta del request dentro del buffer con el metodo 
 * seleccionado.
**/
int request_marshal(buffer *b, const enum socks_reply_status status);

enum socks_reply_status errno_to_socks(int e);

#include <netdb.h>
#include <arpa/inet.h>

enum socks_reply_status cmd_resolve(struct request *request, struct sockaddr **originaddr, socklen_t *originallen, int *domain);
#endif