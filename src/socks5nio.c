#include "../includes/socks5nio.h"

enum socks_v5state
{
    /*
        TODO: completar explicaciones!
    */
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

struct hello_st
{
    buffer *rb, *wb;
    struct hello_parser parser;
    uint8_t method;
};

struct request_st
{
    buffer *rb, *wb;
    struct request request;
    struct request_parser parser;

    /** resumen de la respuesta a enviar **/
    enum socks_reply_status status;

    /** a donde nos tenemos que conectar **/
    struct sockaddr_storage *origin_addr;
    socklen_t *origin_addr_len;
    int *origin_domain;
    const int *client_fd;
    int *origin_fd;
};

struct connecting
{
    buffer *wb;
    const int *client_fd;
    int *origin_fd;
    enum socks_reply_status *status;
};

struct copy
{
    /** el otro fd **/
    int *fd;

    /** buffers para hacer la copia **/
    buffer *rb, *wb;

    /** chequear para saber si cerrar la escritura o la lectura **/
    fd_interest duplex;

    struct copy *other;
};

struct socks5
{
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_fd;

    /** resolucion de la direccion del origin server **/
    struct addrinfo *origin_resolution;

    /** intento actual de la direccion del origin server **/
    struct addrinfo *origin_resolution_current;

    /** informacion del origin server **/
    struct sockaddr_storage origin_addr;
    socklen_t origin_addr_len;
    int origin_domain;
    int origin_fd;

    /** maquinas de estados **/
    struct state_machine stm;

    /** estados para el client_fd **/
    union
    {
        struct hello_st hello;
        struct request_st request;
        struct copy copy;
    } client;

    /** estados para el origin_fd **/
    union
    {
        struct connecting conn;
        struct copy copy;
    } orig;

    /** buffers para write y read **/
    uint8_t raw_buff_a[MAX_BUFF_SIZE], raw_buff_b[MAX_BUFF_SIZE];
    buffer read_buffer, write_buffer;

    /** cantidad de referencias a este objeto. Si es 1 se debe destruir **/
    unsigned references;

    /** siguiente en el pool **/
    struct socks5 *next;
};

/*
Pool de 'struct socks5', para ser reusados.
Como tenemos un único hilo que emite eventos, no necesitamos barreras de contención.
*/

static const unsigned max_pool = 50; // tamaño máximo
static unsigned pool_size = 0;       // tamaño actual

static struct socks5 *pool = 0;

static const struct state_definition *socks_describe_status(void);
static void socks5_destroy(struct socks5 *state);
static void socksv5_write(struct selector_key *key);
static void socksv5_read(struct selector_key *key);
static void socksv5_block(struct selector_key *key);
static void socksv5_close(struct selector_key *key);
static unsigned copy_r(struct selector_key *key);
static unsigned copy_w(struct selector_key *key);
static void hello_read_init(const unsigned state, struct selector_key *key);
static void hello_read_close(const unsigned state, struct selector_key *key);
static unsigned hello_read(struct selector_key *key);
static unsigned hello_write(struct selector_key *key);
static void request_init(const unsigned state, struct selector_key *key);
static void request_read_close(const unsigned state, struct selector_key *key);
static unsigned request_read(struct selector_key *key);
static unsigned request_resolv_done(struct selector_key *key);
static void request_connecting_init(const unsigned state, struct selector_key *key);
static unsigned request_connecting(struct selector_key *key);
static unsigned request_write(struct selector_key *key);
static void copy_init(const unsigned state, struct selector_key *key);

// definición de handlers para cada estado
static const struct state_definition client_statbl[] = {

    {
        .state = HELLO_READ,
        .on_arrival = hello_read_init,
        .on_departure = hello_read_close,
        .on_read_ready = hello_read,
    },
    {
        .state = HELLO_WRITE,
        .on_write_ready = hello_write,
    },
    // {
    //     .state              = AUTH_READ,
    //     .on_arrival         = auth_init,
    //     .on_departure       = auth_read_close,
    //     .on_read_ready      = auth_read,
    // }, {
    //     .state              = AUTH_WRITE,
    //     .on_write_ready     = auth_write
    // },
    {
        .state = REQUEST_READ,
        .on_arrival = request_init,
        .on_departure = request_read_close,
        .on_read_ready = request_read,
    },
    {
        .state = REQUEST_RESOLV,
        .on_block_ready = request_resolv_done,
    },
    {
        .state = REQUEST_CONNECTING,
        .on_arrival = request_connecting_init,
        .on_write_ready = request_connecting,
    },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = request_write,
    },
    {
        .state = COPY,
        .on_arrival = copy_init,
        .on_read_ready = copy_r,
        .on_write_ready = copy_w,
    },
    {
        .state = DONE,
    },
    {
        .state = ERROR,
    }};

const struct fd_handler socks5_handler = {
    .handle_read = socksv5_read,
    .handle_write = socksv5_write,
    .handle_block = socksv5_block,
    .handle_close = socksv5_close,
};

static struct socks5 *socks5_new(int client_fd)
{
    struct socks5 *ret;
    if (pool == NULL)
    {
        ret = malloc(sizeof(*ret));
    }
    else
    {
        ret = pool;
        pool = pool->next;
        ret->next = 0;
    }
    if (ret == NULL)
    {
        return NULL;
    }
    memset(ret, 0x00, sizeof(*ret));

    ret->origin_fd = -1;
    ret->client_fd = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);
    //TODO: falta completar...
    ret->stm.states = client_statbl;
    ret->stm.initial = HELLO_READ;
    ret->stm.max_state = ERROR;
    stm_init(&(ret->stm));

    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);
    return ret;
}

/** handler del socket pasivo que atiende conexiones socks5 **/
void socksv5_passive_accept(struct selector_key *key)
{
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct socks5 *state = NULL;

    const int client = accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client == -1)
    {
        goto fail;
    }
    if (selector_fd_set_nio(client) == -1)
    {
        goto fail;
    }
    state = socks5_new(client);
    if (state == NULL)
    {
        // TODO: no aceptar conexiones hasta que se libere alguna
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;
    if (SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler, OP_READ, state))
    {
        goto fail;
    }
    return;
fail:
    if (client != -1)
    {
        close(client);
    }
    socks5_destroy(state);
}

/** libera pools internos **/
void socksv5_pool_destroy(void)
{
}
// callback del parser utilizado en 'read_hello'
static void on_hello_method(void *data, const uint8_t method)
{
    uint8_t *selected = (uint8_t *)data;

    if (method == METHOD_NO_AUTHENTICATION_REQUIRED)
    {
        *selected = method;
    }
}

// inicializa las variables de los estados HELLO_...
static void hello_read_init(const unsigned state, struct selector_key *key)
{
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    d->parser.data = &d->method;
    d->parser.on_authentication_method = on_hello_method, hello_parser_init(&d->parser);
}

static unsigned hello_process(const struct hello_st *d);

// lee todos los bytes del mensaje de tipo 'hello' e inicia su proceso
static unsigned hello_read(struct selector_key *key)
{
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_READ;
    bool error = false;
    uint8_t *ptr;
    size_t count;

    ptr = buffer_write_ptr(d->rb, &count);
    ssize_t n = recv(key->fd, ptr, count, 0);
    if (n > 0)
    {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        if (hello_is_done(st, 0))
        {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE))
            {
                ret = hello_process(d);
            }
            else
            {
                ret = ERROR;
            }
        }
    }
    else
    {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

// procesamiento del mensaje 'hello'
static unsigned hello_process(const struct hello_st *d)
{
    unsigned ret = HELLO_WRITE;

    uint8_t m = d->method;
    const uint8_t r = (m == METHOD_NO_ACCEPTABLE_METHODS) ? 0xFF : 0x00;
    if (-1 == hello_marshal(d->wb, r))
    {
        ret = ERROR;
    }
    if (m == METHOD_NO_ACCEPTABLE_METHODS)
    {
        ret = ERROR;
    }

    return ret;
}

// libera los recursos al salir de HELLO_READ
static void hello_read_close(const unsigned state, struct selector_key *key)
{
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    hello_parser_close(&d->parser);
}

// escribe todos los bytes de la respuesta al mensaje 'hello'
static unsigned hello_write(struct selector_key *key)
{
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    unsigned ret = HELLO_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(d->wb, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n == -1)
    {
        ret = ERROR;
    }
    else
    {
        buffer_read_adv(d->wb, n);
        if (!buffer_can_read(d->wb))
        {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ))
            {
                ret = REQUEST_READ;
            }
            else
            {
                ret = ERROR;
            }
        }
    }

    return ret;
}

////////////////////////////////////////////////////////////////////////
// REQUEST
////////////////////////////////////////////////////////////////////////

// inicializa las variables de los estados REQUEST_...
static void request_init(const unsigned state, struct selector_key *key)
{
    struct request_st *d = &ATTACHMENT(key)->client.request;

    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    d->parser.request = &d->request;
    d->status = status_general_socks_server_failure;
    request_parser_init(&d->parser);
    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->origin_fd = &ATTACHMENT(key)->origin_fd;

    d->origin_addr = &ATTACHMENT(key)->origin_addr;
    d->origin_addr_len = &ATTACHMENT(key)->origin_addr_len;
    d->origin_domain = &ATTACHMENT(key)->origin_domain;
}

static unsigned request_process(struct selector_key *key, struct request_st *d);

// lee todos los bytes del mensaje de tipo 'request' e inicia su proceso
static unsigned request_read(struct selector_key *key)
{
    struct request_st *d = &ATTACHMENT(key)->client.request;

    buffer *b = d->rb;
    unsigned ret = REQUEST_READ;
    bool error = false;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(b, &count);
    n = recv(key->fd, ptr, count, 0);
    if (n > 0)
    {
        buffer_write_adv(b, n);
        int st = request_consume(b, &d->parser, &error);
        if (request_is_done(st, 0))
        {
            ret = request_process(key, d);
        }
    }
    else
    {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static unsigned request_write(struct selector_key *key)
{
    struct request_st *d = &ATTACHMENT(key)->client.request;

    buffer *b = d->wb;
    unsigned ret = REQUEST_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;
    ptr = buffer_read_ptr(b, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n == -1)
    {
        ret = ERROR;
    }
    else
    {
        buffer_read_adv(b, n);
        if (!buffer_can_read(b))
        {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ))
            {
                ret = COPY;
            }
            else
            {
                ret = ERROR;
            }
        }
    }
    return ret;
}

static unsigned request_connect(struct selector_key *key, struct request_st *d);

static void *request_resolv_blocking(void *data);

/*
Procesa el mensaje de tipo 'request'.
Únicamente soportamos el comando cmd_connect.

Si tenemos la dirección IP intentamos establecer la conexión.

Si tenemos que resolver el nombre (operación bloqueante), disparamos
la resolución en un thread que luego notificará al selector que ha terminado.
*/
static unsigned request_process(struct selector_key *key, struct request_st *d)
{
    unsigned ret;
    pthread_t tid;

    switch (d->request.cmd)
    {

    case cmd_connect:
        // esto mejoraría enormemente de haber usado sockaddr_storage en el request

        switch (d->request.dest_addr_type)
        {
        case ipv4_type:
        {
            ATTACHMENT(key)->origin_domain = AF_INET;
            d->request.dest_addr.ipv4.sin_port = d->request.dest_port;
            ATTACHMENT(key)->origin_addr_len = sizeof(d->request.dest_addr.ipv4);
            memcpy(&ATTACHMENT(key)->origin_addr, &d->request.dest_addr,
                   sizeof(d->request.dest_addr.ipv4));
            ret = request_connect(key, d);
            break;
        }
        case ipv6_type:
        {
            ATTACHMENT(key)->origin_domain = AF_INET6;
            d->request.dest_addr.ipv6.sin6_port = d->request.dest_port;
            ATTACHMENT(key)->origin_addr_len = sizeof(d->request.dest_addr.ipv6);
            memcpy(&ATTACHMENT(key)->origin_addr, &d->request.dest_addr,
                   sizeof(d->request.dest_addr.ipv6));
            ret = request_connect(key, d);
            break;
        }
        case domainname_type:
        {
            struct selector_key *k = (struct selector_key *)malloc(sizeof(*key));
            if (k == NULL)
            {
                ret = REQUEST_WRITE;
                d->status = status_general_socks_server_failure;
                selector_set_interest_key(key, OP_WRITE);
            }
            else
            {
                // TODO: change when migration to DoH
                memcpy(k, key, sizeof(*k));
                if (pthread_create(&tid, 0, request_resolv_blocking, k) == -1)
                {
                    ret = REQUEST_WRITE;
                    d->status = status_general_socks_server_failure;
                    selector_set_interest_key(key, OP_WRITE);
                }
                else
                {
                    ret = REQUEST_RESOLV;
                    selector_set_interest_key(key, OP_NOOP);
                }
            }
            break;
        }
        default:
        {
            ret = REQUEST_WRITE;
            d->status = status_address_type_not_supported;
            selector_set_interest_key(key, OP_WRITE);
        }
        }
        break;

    case cmd_bind:
    // Unsupported
    case cmd_udp:
    // Unsupported
    default:
        d->status = status_command_not_supported;
        ret = REQUEST_WRITE;
        break;
    }

    return ret;
}

/*
Realiza la resolución de DNS bloqueante.
Una vez resuelto notifica al selector para que el evento esté disponible en la próxima iteración
*/
//TODO: cambiar para cuando usemos DoH
static void *request_resolv_blocking(void *data)
{
    struct selector_key *key = (struct selector_key *)data;
    struct socks5 *s = ATTACHMENT(key);

    pthread_detach(pthread_self());
    s->origin_resolution = 0;
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,     // Allow IPv4 or IPv6
        .ai_socktype = SOCK_STREAM, // Datagram socket
        .ai_flags = AI_PASSIVE,     // For wildcard IP address
        .ai_protocol = 0,           // Any protocol
        .ai_canonname = NULL,
        .ai_addr = NULL,
        .ai_next = NULL,
    };

    char buff[7];
    snprintf(buff, sizeof(buff), "%d", ntohs(s->client.request.request.dest_port));

    getaddrinfo(s->client.request.request.dest_addr.fqdn, buff, &hints, &s->origin_resolution);

    selector_notify_block(key->s, key->fd);

    free(data);

    return 0;
}

// procesa el resultado de la resolución de nombres
static unsigned request_resolv_done(struct selector_key *key)
{
    struct request_st *d = &ATTACHMENT(key)->client.request;
    struct socks5 *s = ATTACHMENT(key);

    if (s->origin_resolution == 0)
    {
        d->status = status_general_socks_server_failure;
    }
    else
    {
        s->origin_domain = s->origin_resolution->ai_family;
        s->origin_addr_len = s->origin_resolution->ai_addrlen;
        memcpy(&s->origin_addr, s->origin_resolution->ai_addr, s->origin_resolution->ai_addrlen);
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }

    return request_connect(key, d);
}

static void request_read_close(const unsigned state, struct selector_key *key)
{
    struct request_st *d = &ATTACHMENT(key)->client.request;

    request_close(&d->parser);
}

////////////////////////////////////////////////////////////////////
// REQUEST CONNECT
////////////////////////////////////////////////////////////////////
static void request_connecting_init(const unsigned state, struct selector_key *key)
{
    struct connecting *d = &ATTACHMENT(key)->orig.conn;

    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->origin_fd = &ATTACHMENT(key)->origin_fd;
    d->status = &ATTACHMENT(key)->client.request.status;
    d->wb = &ATTACHMENT(key)->write_buffer;
}

// intenta establecer una conexión con el origin server
static unsigned request_connect(struct selector_key *key, struct request_st *d)
{
    bool error = false;
    enum socks_reply_status status = d->status;
    int *fd = d->origin_fd;
    const char *err_msg = NULL;
    unsigned ret = REQUEST_CONNECTING;
    *fd = socket(ATTACHMENT(key)->origin_domain, SOCK_STREAM, 0);
    if (*fd == -1)
    {
        error = true;
        goto finally;
    }

    if (selector_fd_set_nio(*fd) == -1)
    {
        err_msg = "getting server ipv4 socket flags";
        goto finally;
    }

    if (connect(*fd, (const struct sockaddr *)&ATTACHMENT(key)->origin_addr,
                ATTACHMENT(key)->origin_addr_len) == -1)
    {

        if (errno == EINPROGRESS)
        {
            // hay que esperar a la conexión

            // dejamos de pollear el socket del cliente
            selector_status st = selector_set_interest_key(key, OP_NOOP);
            if (st != SELECTOR_SUCCESS)
            {
                error = true;
                goto finally;
            }

            // esperamos la conexión en el nuevo socket
            st = selector_register(key->s, *fd, &socks5_handler, OP_WRITE, key->data);

            if (st != SELECTOR_SUCCESS)
            {
                error = true;
                goto finally;
            }
            ATTACHMENT(key)->references += 1;
        }
        else
        {
            status = errno_to_socks(errno);
            error = true;
            goto finally;
        }
    }

finally:
    return ret;
}

// la conexión ha sido establecida (o falló), parsear respuesta
static unsigned request_connecting(struct selector_key *key)
{
    int error;
    socklen_t len = sizeof(error);
    unsigned ret = REQUEST_CONNECTING;

    struct socks5 *data = ATTACHMENT(key);
    int *fd = data->orig.conn.origin_fd;
    if (getsockopt(*fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0)
    {
        //Escribirle en el buffer de escritura al cliente
        selector_set_interest(key->s, *data->orig.conn.client_fd, OP_WRITE);
        
        if (error == 0)
        {
            data->client.request.status = status_succeeded;
        }
        else {
            data->client.request.status = errno_to_socks(error);
        }

        if (-1 != request_marshal(data->client.request.wb, data->client.request.status, data->client.request.request.dest_addr_type, data->client.request.request.dest_addr, data->client.request.request.dest_port))
        {
            selector_set_interest(key->s, *data->orig.conn.origin_fd, OP_READ);
            ret = REQUEST_WRITE;
        }
        else {
            ret = ERROR;
        }    
    }

    return ret;
}

static void copy_init(const unsigned state, struct selector_key *key)
{
    struct copy *d = &ATTACHMENT(key)->client.copy;

    d->fd = &ATTACHMENT(key)->client_fd;
    d->rb = &ATTACHMENT(key)->read_buffer;
    d->wb = &ATTACHMENT(key)->write_buffer;
    d->duplex = OP_READ | OP_WRITE;
    d->other = &ATTACHMENT(key)->orig.copy;

    d = &ATTACHMENT(key)->orig.copy;
    d->fd = &ATTACHMENT(key)->origin_fd;
    d->rb = &ATTACHMENT(key)->write_buffer;
    d->wb = &ATTACHMENT(key)->read_buffer;
    d->duplex = OP_READ | OP_WRITE;
    d->other = &ATTACHMENT(key)->client.copy;
}

static const struct state_definition *socks5_describe_states(void)
{
    return client_statbl;
}

// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la máquina de estados.

static void socksv5_done(struct selector_key *key)
{
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };

    for (unsigned i = 0; i < N(fds); i++)
    {
        if (fds[i] != -1)
        {
            if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i]))
            {
                abort();
            }
            close(fds[i]);
        }
    }
}

static void socksv5_read(struct selector_key *key)
{
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if (ERROR == st || DONE == st)
    {
        socksv5_done(key);
    }
}

static void socksv5_write(struct selector_key *key)
{
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if (ERROR == st || DONE == st)
    {
        socksv5_done(key);
    }
}

static void socksv5_block(struct selector_key *key)
{
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if (ERROR == st || DONE == st)
    {
        socksv5_done(key);
    }
}

//TODO: finish socks5_destroy
static void socks5_destroy(struct socks5 *state)
{
}

static void socksv5_close(struct selector_key *key)
{
    socks5_destroy(ATTACHMENT(key));
}

/*
Computa los intereses en base a la disponibilidad de los buffer.
La variable duplex nos permite saber su alguna vía ya fue cerrada.
Arranca OP_READ | OP_WRITE.
*/

static fd_interest copy_compute_interests(fd_selector s, struct copy *d)
{
    fd_interest ret = OP_NOOP;

    if (((d->duplex & OP_READ) && buffer_can_write(d->rb)) )
    {
        ret |= OP_READ;
    }
    if ((d->duplex & OP_WRITE) && buffer_can_read(d->wb) )
    {
        ret |= OP_WRITE;
    }
    if (SELECTOR_SUCCESS != selector_set_interest(s, *d->fd, ret))
    {
        abort();
    }
    return ret;
}

// elige la estructura de copia correcta de cada fd (origin o client)
static struct copy *copy_ptr(struct selector_key *key)
{
    struct copy *d = &ATTACHMENT(key)->client.copy;

    if (*d->fd == key->fd)
    {
        // ok
    }
    else
    {
        d = d->other;
    }

    return d;
}

// lee bytes de un socket y los encola para ser escritos en otro socket
static unsigned copy_r(struct selector_key *key)
{
    struct copy *d = copy_ptr(key);

    assert(*d->fd == key->fd);
    size_t size;
    ssize_t n;
    buffer *b = d->rb;
    unsigned ret = COPY;

    uint8_t *ptr = buffer_write_ptr(b, &size);
    n = recv(key->fd, ptr, size, 0);
    if (n <= 0)
    {
        shutdown(*d->fd, SHUT_RD);
        d->duplex &= ~OP_READ;
        if (*d->other->fd != -1)
        {
            shutdown(*d->other->fd, SHUT_WR);
            d->other->duplex &= ~OP_WRITE;
        }
    }
    else
    {
        buffer_write_adv(b, n);
    }
    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);
    if (d->duplex == OP_NOOP)
    {
        ret = DONE;
    }

    return ret;
}

// escribe bytes encolados
static unsigned copy_w(struct selector_key *key)
{
    struct copy *d = copy_ptr(key);

    assert(*d->fd == key->fd);
    size_t size;
    ssize_t n;
    buffer *b = d->wb;
    unsigned ret = COPY;

    uint8_t *ptr = buffer_read_ptr(b, &size);
    n = send(key->fd, ptr, size, MSG_NOSIGNAL);
    if (n == -1)
    {
        shutdown(*d->fd, SHUT_WR);
        d->duplex &= ~OP_WRITE;
        if (*d->other->fd != -1)
        {
            shutdown(*d->other->fd, SHUT_RD);
            d->other->duplex &= ~OP_READ;
        }
    }
    else
    {
        buffer_read_adv(b, n);
    }
    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);
    if (d->duplex == OP_NOOP)
    {
        ret = DONE;
    }

    return ret;
}
