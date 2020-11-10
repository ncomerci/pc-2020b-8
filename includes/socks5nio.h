#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "hello.h"
#include "request.h"
#include "buffer.h"
#include "stm.h"
#include "socks5nio.h"
#include "netutils.h"
#include "selector.h"
#include "auth.h"
#include "logger.h"
#include "httpsniff.h"
#include "doh.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)
/** handler del socket pasivo que atiende conexiones socks5 **/
void socksv5_passive_accept(struct selector_key *key);

/** libera pools internos **/
void socksv5_pool_destroy(void);

#endif