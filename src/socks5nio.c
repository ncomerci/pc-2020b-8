#include "../includes/socks5nio.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "../includes/hello.h"
#include "../includes/request.h"
#include "../includes/buffer.h"
#include "../includes/stm.h"
#include "../includes/socks5nio.h"
#include "../includes/netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

enum socks_v5state{
    HELLO_READ,
    HELLO_WRITE,
    REQUEST_READ,
    REQUEST_RESOLV,
    REQUEST_CONNECTING,
    REQUEST_WRITE,
    COPY,
    DONE,
    ERROR
};

struct hello_st{
    buffer      *rb, *wb;
    struct      hello_parser parser;
    uint8_t     method;
};

struct request_st{
    buffer *rb, *wb;
    struct request request;
    struct request_parser parser;

    /** resumen de la respuesta a enviar **/
    enum socks_reply_status status;

    /** a donde nos tenemos que conectar **/
    struct sockaddr_storage     *origin_addr;
    socklen_t                   *origin_addr_len;
    int                         *origin_domain;
    const int                   *client_fd;
    int                         *origin_fd;
};

struct connecting{
    buffer      *wb;
    const int   *client_fd;
    int         *origin_fd;
    enum socks_reply_status *status;
};

struct copy{
    /** el otro fd **/
    int         *fd;

    /** buffers para hacer la copia **/
    buffer *rb, *wb;

    /** chequear para saber si cerrar la escritura o la lectura **/
    fd_interest duplex;

    struct copy *other;

}

struct socks5{
    struct sockaddr_storage     client_addr;
    socklen_t                   client_addr_len;
    int                         client_fd;

    /** resolucion de la direccion del origin server **/
    struct addrinfo             *origin_resolution;

    /** intento actual de la direccion del origin server **/
    struct addrinfo             *origin_resolution_current;

    /** informacion del origin server **/
    struct sockaddr_storage     origin_addr;
    socklen_t                   origin_addr_len;
    int                         origin_domain;
    int                         origin_fd;

    /** maquinas de estados **/
    struct state_machine            stm;

    /** estados para el client_fd **/
    union {
        struct hello_st             hello;
        struct request_st           request;
        struct copy                 copy;
    } client;

    /** estados para el origin_fd **/
    union {
        struct connecting           conn;
        struct copy                 copy;
    } orig;

    /** buffers para write y read **/
    uint8_t raw_buff_a[MAX_BUFF_SIZE], raw_buff_b[MAX_BUFF_SIZE];
    buffer read_buffer, write_buffer;

    /** cantidad de referencias a este objeto. Si es 1 se debe destruir **/
    unsigned references;
    
    /** siguiente en el pool **/
    struct socks5 *next;
};

static struct socks5 *pool = 0;

static const struct state_definition *socks_describe_status(void);

static struct socks5 *socks5_new(int client_fd){
    struct socks5 *ret;
    if(pool == NULL){
        ret = malloc(sizeof(*ret));
    }
    else{
        ret = pool;
        pool = pool->next;
        ret->next = 0;
    }
    if(ret == NULL){
        goto finally;
    }
    memset(ret,0x00. sizeof(*ret));

    ret->origin_fd = -1;
    ret->client_fd = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);
}

static void hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = = &ATTACHMENT(key)->client.hello;

    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    d->parser.data = &d->method;
    d->parser.on_authentication_method = on_hello_method, hello_parser_init(&d->parser);
}

static unsigned hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_READ;
    bool error = false;
    // TODO: hay que seguir esta parte...
}

// elige la estructura de copia correcta de cada fd (origin o client)
static struct copy *copy_ptr(struct selector_key *key) {
    struct copy *d = &ATTACHMENT(key)->client.copy;

    if(*d->fd == hek->fd) {
        // ok
    }
    else {
        d = d->other;
    }

    return d;
}

static void socksv5_read(struct selector_key *key) {
    
}

static void socksv5_block(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void socks5_done(struct selector_key *key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };

    for(unsigned i = 0; i < N(fds) ; i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregistered_fd(key->s, fds[i])) {
                abort();
            }
        }

        // TODO: hay que seguir esta parte...
    }
}