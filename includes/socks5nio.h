#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H

#include "selector.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

/** handler del socket pasivo que atiende conexiones socks5 **/
void socksv5_passive_accept(struct selector_key *key);


#endif