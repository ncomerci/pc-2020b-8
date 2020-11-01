#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H
#define MAX_BUFF_SIZE 2048
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "hello.h"
#include "request.h"
#include "buffer.h"
#include "stm.h"
#include "socks5nio.h"
#include "netutils.h"
#include "selector.h"

#define ATTACHMENT(key) 
/** handler del socket pasivo que atiende conexiones socks5 **/
void socksv5_passive_accept(struct selector_key *key);

/** libera pools internos **/
void socksv5_pool_destroy(void);

#endif