#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H
#define MAX_BUFF_SIZE 2048
#include <netdb.h>
#include "selector.h"

/** handler del socket pasivo que atiende conexiones socks5 **/
void socksv5_passive_accept(struct selector_key *key);

/** libera pools internos **/
void socksv5_pool_destroy(void);

#endif