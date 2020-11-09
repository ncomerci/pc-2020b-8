#include "../includes/doh.h"

static char *host = "localhost";
static char *ip = "127.0.0.1";
static char *path = "/dns-query"; //TODO: cambiar a getnsrecord antes de entregar
static char *query = "?dns=";
static size_t port = 8053;

static void doh_init(struct DoH *doh);
static void doh_close(struct selector_key *key);
static void doh_done(struct selector_key *key);
static void doh_write(struct selector_key *key);

const struct fd_handler doh_handler = {
    .handle_read = NULL,
    .handle_write = doh_write,
    .handle_block = NULL,
    .handle_close = doh_close,
};

static void doh_init(struct DoH *doh) {

    memset(doh->raw_buff, 0, MAX_BUFF_SIZE);
    buffer_init(&doh->buff, MAX_BUFF_SIZE, doh->raw_buff);
    doh->host = host;
    doh->ip = ip;
    doh->port = port;
    doh->path = path;
    doh->query = query;
    doh->fqdn = NULL;
}

static void doh_close(struct selector_key *key) {
    free(DOH_ATTACH(key));
}

static void doh_done(struct selector_key *key) {

    const int fd = DOH_ATTACH(key)->doh_fd;

    if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fd))
    {
        abort();
    }
    close(fd);

}

static void doh_write(struct selector_key *key) {
    int error;
    socklen_t len = sizeof(error);
    struct DoH * doh = DOH_ATTACH(key);

    if(getsockopt(doh->doh_fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
        
        if (error != 0)
        {
            selector_set_interest(key->s, doh->client_fd, OP_WRITE);
            doh->origin_resolution = NULL;
            doh_done(key);
        }
        else {
            // enviar consulta dns
        }
    }
}

int create_doh_request(fd_selector s, char *fqdn, struct addrinfo *origin_resolution, int client_fd) {

    struct DoH* doh = malloc(sizeof(struct DoH));

    if(doh == NULL) {
        goto fail;
    }

    doh_init(doh);
    doh->fqdn = fqdn;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1){
        goto fail;
    }

    if (selector_fd_set_nio(fd) == -1)
    {
        goto fail;
    }

    doh->doh_fd = fd;
    doh->client_fd = client_fd;
    doh->origin_resolution = origin_resolution;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(doh->port);
    
    if(inet_pton(addr.sin_family, doh->ip, &addr.sin_addr) <= 0)
    {
        goto fail;
    } 

    if(connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) == -1) 
    {
        if (errno == EINPROGRESS)
        {
            // hay que esperar a la conexión

            // // dejamos de pollear el socket del cliente
            // selector_status st = selector_set_interest_key(key, OP_NOOP);
            // if (st != SELECTOR_SUCCESS)
            // {
            //     goto fail;
            // }

            // esperamos la conexión en el nuevo socket
            selector_status st = selector_register(s, fd, &doh_handler, OP_WRITE, doh);
            if (st != SELECTOR_SUCCESS)
            {
                goto fail;
            }
        }
        else {
            goto fail; 
        }
    }

    return 0;

fail:
    free(doh);
    return -1;
}