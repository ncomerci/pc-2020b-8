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
#include "netutils.h"
#include "selector.h"
#include "auth.h"
#include "logger.h"
#include "httpsniff.h"
#include "pop3sniff.h"
#include "main.h"
#include "args.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

struct write{
    uint8_t raw_buff[MAX_BUFF_SIZE];
    buffer wb;
    fd_selector selector;
};

/** handler del socket pasivo que atiende conexiones socks5 **/
void socksv5_passive_accept(struct selector_key *key);

/** libera pools internos **/
void socksv5_pool_destroy(void);

void write_handler(struct selector_key * key);


#endif