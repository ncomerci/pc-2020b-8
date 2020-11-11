#include "../includes/mng.h"
#define MAX_BUFF_SIZE 2048
#define MNG_ATTACHMENT(key) ((struct mng*)key->data)
#define N(x) (sizeof(x)/sizeof((x)[0]))

static void auth_init(const unsigned state, struct selector_key *key);
static unsigned auth_read(struct selector_key *key);
static unsigned auth_write(struct selector_key *key);
static void auth_read_close(const unsigned state, struct selector_key *key);
static void cmd_init(const unsigned state, struct selector_key *key);
static unsigned cmd_read(struct selector_key *key);
static unsigned cmd_write(struct selector_key *key);
static void mng_write(struct selector_key *key);
static void mng_read(struct selector_key *key);
static void mng_close(struct selector_key *key);

enum mng_state
{
    /*
    **  Estado: AUTH_READ
    **  Intereses: OP_READ
    **  Trasiciones: AUTH_READ | AUTH_WRITE | ERROR | DONE
    **  Lee el primer mensage del cliente y lo parsea.
    */
    AUTH_READ,
    /* 
    **  Estado: AUTH_WRITE
    **  Intereses: OP_WRITE
    **  Transiciones: AUTH_WRITE | CMD_READ | DONE | ERROR
    **  Se encarga de enviar la respuesta del primer mensage del cliente
    */
    AUTH_WRITE,
    /* 
    **  Estado: CMD_READ
    **  Intereses: OP_READ
    **  Transiciones: CMD_READ | CMD_WRITE | DONE | ERROR
    **  Lee el comando que envia el usuario y lo parsea
    */
    CMD_READ,
    /* 
    **  Estado: CMD_WRITE
    **  Intereses: OP_WRITE
    **  Transiciones: CMD_READ | CMD_WRITE | DONE | ERROR
    **  Se encarga de enviar la respuesta del comando con su resultado,
    **  vuelve a CMD_READ cuando termina de enviar la respuesta.
    */
    CMD_WRITE,

    /* Estados terminales */
    DONE,

    ERROR
};


static const struct state_definition client_mngstates[] = {

    {
        .state = AUTH_READ,
        .on_arrival = auth_init,
        .on_departure = auth_read_close,
        .on_read_ready = auth_read,
    },

    {
        .state = AUTH_WRITE,
        .on_write_ready = auth_write,
    },

    {
        .state = CMD_READ,
        .on_arrival = cmd_init,
        .on_read_ready = cmd_read,
    },

    {
        .state = CMD_WRITE,
        .on_write_ready = cmd_write,
    },

    {
        .state = DONE,
    },

    {
        .state = ERROR,
    }
};

struct auth_st{
    buffer *rb, *wb;
    auth_parser parser;
    struct usr* usr;
    struct pass* pass;
    uint8_t status;
};

struct cmd_st{
    buffer *rb, *wb;
    cmd_parser parser;
};

struct mng{
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_fd;

    struct state_machine stm;

    union{
        struct auth_st auth;
        struct cmd_st cmd;
    }client;

    struct cmd_st cmd;
    /** buffers para write y read **/
    uint8_t raw_buff_a[MAX_BUFF_SIZE], raw_buff_b[MAX_BUFF_SIZE];
    buffer read_buffer, write_buffer;
};

static struct mng* mng_new(int client_fd){
    struct mng *ret;
    ret = malloc(sizeof(*ret));
    if(ret == NULL){
        return NULL;
    }
    memset(ret,0x00,sizeof(*ret));
    ret->client_fd = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);
    ret->stm.states = client_mngstates;
    ret->stm.initial = AUTH_READ;
    ret->stm.max_state = ERROR;
    stm_init(&(ret->stm));
    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);
    
    return ret;
}



const struct fd_handler mng_handler = {
    .handle_read = mng_read,
    .handle_write = mng_write,
    // .handle_block = mng_block,
    .handle_close = mng_close,
};

static void mng_done(struct selector_key *key){
    // struct mng *mng = MNG_ATTACHMENT(key);
    int fd = MNG_ATTACHMENT(key)->client_fd;
    if (fd!= -1){
        if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fd))
        {
            abort();
        }
        close(fd);
    }
}

static void mng_write(struct selector_key *key){
    struct state_machine *stm = &MNG_ATTACHMENT(key)->stm;
    const enum mng_state st = stm_handler_write(stm, key);

    if (ERROR == st || DONE == st)
    {
        mng_done(key);
    }
}

static void mng_read(struct selector_key *key){
    struct state_machine *stm = &MNG_ATTACHMENT(key)->stm;
    const enum mng_state st = stm_handler_read(stm, key);
    if (ERROR == st || DONE == st){
        mng_done(key);
    }   
}

static void mng_close(struct selector_key *key){
    if(key->data != NULL) {
        free(key->data);
        key->data = NULL;
    }
}

void mng_passive_accept(struct selector_key * key){
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct mng *state = NULL;
    const int client = accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (selector_fd_set_nio(client) == -1)
    {
        goto fail;
    }
    state = mng_new(client);
    if (state == NULL)
    {
        // TODO: no aceptar conexiones hasta que se libere alguna
        goto fail;
    }

    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;
    if (SELECTOR_SUCCESS != selector_register(key->s, client, &mng_handler, OP_READ, state))
    {
        goto fail;
    }
    return;

fail:
    if (client != -1)
    {
        close(client);
    }
    mng_close(key);
}



////////////////////////////////////////////////////////////////////////
// AUTH
////////////////////////////////////////////////////////////////////////

// inicializa las variables de los estados AUTH...
static void auth_init(const unsigned state, struct selector_key *key)
{
    struct auth_st *d = &MNG_ATTACHMENT(key)->client.auth;
    d->rb = &(MNG_ATTACHMENT(key)->read_buffer);
    d->wb = &(MNG_ATTACHMENT(key)->write_buffer);
    auth_parser_init(&d->parser,AUTH_MNG);
    d->usr = &d->parser.usr;
    d->pass = &d->parser.pass;
}


static uint8_t check_credentials(const struct auth_st *d){
    int nusers = get_args_nusers();
    struct users *users = get_args_users();

    for(int i = 0; i < nusers; i++){
        if((strcmp(users[i].name,(char*)d->usr->uname) == 0) && (strcmp(users[i].pass,(char*)d->pass->passwd) == 0)){
            return AUTH_SUCCESS;
        }
    }
    return AUTH_FAIL;
}

static unsigned auth_process(struct auth_st *d){
    unsigned ret = AUTH_WRITE;
    uint8_t status = check_credentials(d);
    if(auth_marshal(d->wb,status,d->parser.version) == -1){
        ret = ERROR;
    }
    d->status = status;
    return ret;
}
static unsigned auth_read(struct selector_key *key){
    unsigned ret = AUTH_READ;
    struct auth_st * d = &MNG_ATTACHMENT(key)->client.auth;
    bool error = false;
    uint8_t *ptr;
    buffer * buff = d->rb;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(buff,&count);
    // struct msghdr msghdr;
    // n = recvmsg(key->fd,&ptr,0);
    n = recv(key->fd,ptr,count,0);
    if (n > 0){
        buffer_write_adv(buff,n);
        int st = auth_consume(buff,&d->parser,&error);
        if(auth_is_done(st,0)){
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE))
            {
                ret = auth_process(d);
                // memcpy(&MNG_ATTACHMENT(key)->socks_info.user_info,&d->parser.usr,sizeof(d->parser.usr));
                
            }
            else{
                ret = ERROR;
            }
        }

    }
    else{
        ret = ERROR;
    }
    return error ? ERROR : ret;
}

static unsigned auth_write(struct selector_key *key){
    struct auth_st * d = &MNG_ATTACHMENT(key)->client.auth;
    unsigned ret = AUTH_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;
    buffer *buff = d->wb;
    ptr = buffer_read_ptr(buff,&count);
    // struct msghdr msghdr;
    // struct iovec iov[1];
    // memset(&msghdr,0,sizeof(msghdr));
    // iov[0].iov_base = ptr;
    // iov[0].iov_len = count;
    // msghdr.msg_iov = iov;
    // msghdr.msg_iovlen = 1;
    // n = sendmsg(key->fd,&msghdr,MSG_NOSIGNAL);
    n = send(key->fd,ptr,count,MSG_NOSIGNAL);
    if(d->status != AUTH_SUCCESS){
        ret = ERROR;
    }
    else if (n > 0){
        buffer_read_adv(buff,n);
        if(!buffer_can_read(buff)){
            if(selector_set_interest_key(key,OP_READ) == SELECTOR_SUCCESS){
                ret = CMD_READ;
            }
            else{
                ret = ERROR;
            }
        }
    }
    return ret;
}

static void auth_read_close(const unsigned state, struct selector_key *key){
    struct auth_st *d = &MNG_ATTACHMENT(key)->client.auth;
    auth_parser_close(&d->parser);
}
////////////////////////////////////////////////////////////////////////
// CMD
////////////////////////////////////////////////////////////////////////

static void cmd_init(const unsigned state, struct selector_key *key){
    struct cmd_st *d = &MNG_ATTACHMENT(key)->client.cmd;
    d->rb = &(MNG_ATTACHMENT(key)->read_buffer);
    d->wb = &(MNG_ATTACHMENT(key)->write_buffer);
    cmd_parser_init(&d->parser);
}

static unsigned cmd_read(struct selector_key *key){
    unsigned ret = CMD_READ;
    struct cmd_st * d = &MNG_ATTACHMENT(key)->client.cmd;
    bool error = false;
    uint8_t *ptr;
    buffer * buff = d->rb;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(buff,&count);
    // struct msghdr msghdr;
    // struct iovec iov[1];
    // memset(&msghdr,0,sizeof(msghdr));
    // iov[0].iov_base = ptr;
    // iov[0].iov_len = count;
    // msghdr.msg_iov = iov;
    // msghdr.msg_iovlen = 1;
    // n = recvmsg(key->fd,&msghdr,0);
    // n = recv(key->fd,ptr,count,0);
    // if (n > 0){
    //     buffer_write_adv(buff,n);
    //     int st = cmd_consume(buff,&d->parser,&error);
    //     if(auth_is_done(st,0)){
    //         if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE))
    //         {
    //             ret = auth_process(d);
    //             // memcpy(&MNG_ATTACHMENT(key)->socks_info.user_info,&d->parser.usr,sizeof(d->parser.usr));
                
    //         }
    //         else{
    //             ret = ERROR;
    //         }
    //     }

    // }
    // else{
    //     ret = ERROR;
    // }
    // return error ? ERROR : ret;
}

static unsigned cmd_write(struct selector_key *key){

}