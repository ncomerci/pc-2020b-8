#include "../includes/mng.h"
#define BUFF_SIZE 2048
#define MNG_ATTACHMENT(key) ((struct mng*)key->data)
#define N(x) (sizeof(x)/sizeof((x)[0]))


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
    enum cmd_reply_status *status;
    uint8_t * resp;
    uint8_t resp_len;
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

    // struct cmd_st cmd;
    /** buffers para write y read **/
    uint8_t raw_buff_a[BUFF_SIZE], raw_buff_b[BUFF_SIZE];
    buffer read_buffer, write_buffer;
};

typedef size_t (*query_handler)(struct cmd_st *d);

static void auth_init(struct selector_key *key);
static unsigned auth_read(struct selector_key *key);
static unsigned auth_write(struct selector_key *key);
static void auth_read_close(struct selector_key *key);
static void cmd_init(struct selector_key *key);
static unsigned cmd_read(struct selector_key *key);
static unsigned cmd_write(struct selector_key *key);
static void mng_write(struct selector_key *key);
static void mng_read(struct selector_key *key);
static void mng_close(struct selector_key *key);


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

static size_t transfered_bytes(struct cmd_st *d);
static size_t add_user(struct cmd_st * d);
static size_t historical_conexions(struct cmd_st *d);
static size_t concurrent_conexions(struct cmd_st *d);
static size_t transfered_bytes(struct cmd_st *d);
static size_t historical_conexions(struct cmd_st *d);
static size_t concurrent_conexions(struct cmd_st *d);
static size_t users(struct cmd_st *d);

static size_t del_user(struct cmd_st *d);
static size_t change_pass(struct cmd_st *d);
static size_t set_pass_dissector(struct cmd_st *d);
static size_t set_doh_ip(struct cmd_st *d);
static size_t set_doh_port(struct cmd_st *d);
static size_t set_doh_host(struct cmd_st *d);
static size_t set_doh_path(struct cmd_st *d);
static size_t set_doh_query(struct cmd_st *d);

query_handler handlers[] = {transfered_bytes,historical_conexions,
                            concurrent_conexions,users,add_user,del_user,
                            change_pass,set_pass_dissector,set_doh_ip,set_doh_port,
                            set_doh_host,set_doh_path,set_doh_query};

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
static void auth_init(struct selector_key *key)
{
    struct auth_st *d = &MNG_ATTACHMENT(key)->client.auth;
    d->rb = &(MNG_ATTACHMENT(key)->read_buffer);
    d->wb = &(MNG_ATTACHMENT(key)->write_buffer);
    auth_parser_init(&d->parser,AUTH_MNG);
    d->usr = &d->parser.usr;
    d->pass = &d->parser.pass;
}


static uint8_t check_credentials(const struct auth_st *d){
    // int nadmins = get_args_nadmins();
    // struct users *users = get_args_users();
    if(check_admin_credentials((char*)d->usr->uname,(char*)d->pass->passwd)) return AUTH_SUCCESS;
    // for(int i = 0; i < nadmins; i++){
        
        // struct users admin = get_args_admin(i);
        // if((strcmp(admin.name,(char*)d->usr->uname) == 0) && (strcmp(admin.pass,(char*)d->pass->passwd) == 0)){
            // return AUTH_SUCCESS;
        // }
    // }
    return AUTH_BAD_CREDENTIALS;
}

static unsigned auth_process(struct auth_st *d){
    unsigned ret = AUTH_WRITE;
    // mng_auth_state_to_reply();
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

static void auth_read_close(struct selector_key *key){
    struct auth_st *d = &MNG_ATTACHMENT(key)->client.auth;
    auth_parser_close(&d->parser);
}
////////////////////////////////////////////////////////////////////////
// CMD
////////////////////////////////////////////////////////////////////////

static void cmd_init(struct selector_key *key){
    struct cmd_st *d = &MNG_ATTACHMENT(key)->client.cmd;
    d->rb = &(MNG_ATTACHMENT(key)->read_buffer);
    d->wb = &(MNG_ATTACHMENT(key)->write_buffer);
    cmd_parser_init(&d->parser);
    d->status = &d->parser.status;
    d->resp = NULL;
    d->resp_len = 0;
}


static unsigned cmd_process(struct cmd_st *d){
    unsigned ret = CMD_WRITE;
    size_t nwrite = 0;
    if(d->parser.type == 0x02){
        *d->status = mng_status_succeeded;
    }
    else{
        nwrite = handlers[d->parser.cmd](d);
    }
    if(nwrite == -1){
        *d->status = mng_status_general_server_failure;
        ret = ERROR;
    }
    if(-1 == cmd_marshall(d->wb,*d->status,d->resp,nwrite)){
        ret = ERROR;
    }
    return ret;
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
    n = recv(key->fd,ptr,count,0);
    if (n > 0){
        buffer_write_adv(buff,n);
        int st = cmd_consume(buff,&d->parser,&error);
        if(cmd_is_done(st,0)){
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE))
            {
                ret = cmd_process(d);
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

static unsigned cmd_write(struct selector_key *key){
    struct cmd_st * d = &MNG_ATTACHMENT(key)->client.cmd;
    unsigned ret = CMD_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;
    buffer *buff = d->wb;
    ptr = buffer_read_ptr(buff,&count);
    n = send(key->fd,ptr,count,MSG_NOSIGNAL);
    if (n > 0){
        if(d->parser.type == 0x02){
            ret = DONE;
        }
        else{
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
    }
    else{
        ret = ERROR;
    }
    return ret;
}

static size_t transfered_bytes(struct cmd_st *d){
    size_t nwrite = 7;
    d->resp = malloc(nwrite * sizeof(uint8_t));
    uint64_t bytes = get_total_bytes_transfered();
    d->resp[0] = d->parser.cmd;
    d->resp[1] = 0x01;
    d->resp[2] = 0x04;
    d->resp[3] = bytes >> 24;
    for(int i = 4; i < 7;i++){
        d->resp[i] = (bytes >> (8*(6-i))) & 255;
    }
    *d->status = mng_status_succeeded;
    return nwrite;

}

static size_t add_user(struct cmd_st * d){
    uint8_t type = d->parser.args[0][0];
    if(type != 0 && type != 1){
        *d->status = mng_status_malformed_args;
    }
    char * user = (char*)d->parser.args[1];
    char * pass = (char*)d->parser.args[2];
    *d->status = mng_status_succeeded;

    int ret = type == 0x00 ? add_new_admin(user,pass) : add_new_user(user,pass);
    if (-1 == ret) *d->status = mng_status_max_users_reached;
    else if(-2 == ret) *d->status = mng_status_username_taken;
    return 0;
}

static size_t historical_conexions(struct cmd_st *d){
    size_t nwrite = 5;
    d->resp = malloc(nwrite * sizeof(uint8_t));
        if(d->resp == NULL){
        return -1;
    }
    uint64_t bytes = get_historical_conections();
    d->resp[0] = d->parser.cmd;
    d->resp[1] = 0x01;
    d->resp[2] = 0x02;
    d->resp[3] = bytes >> 8;
    d->resp[4] = bytes & 255;
    *d->status = mng_status_succeeded;
    return nwrite;
}

static size_t concurrent_conexions(struct cmd_st *d){
    size_t nwrite = 5;
    d->resp = malloc(nwrite * sizeof(uint8_t));
    if(d->resp == NULL){
        return -1;
    }
    uint64_t bytes = get_concurrent_conections();
    d->resp[0] = d->parser.cmd;
    d->resp[1] = 0x01;
    d->resp[2] = 0x02;
    d->resp[3] = bytes >> 8;
    d->resp[4] = bytes & 255;
    *d->status = mng_status_succeeded;
    return nwrite;
}

//Que pasa si strlen(users) > 255
static size_t users(struct cmd_st *d){
    size_t nwrite;
    char * users = get_all_users();
    if(users == NULL){
        return -1;
    }
    d->resp = malloc((strlen(users) + 2) * sizeof(uint8_t));
        if(d->resp == NULL){
        return -1;
    }
    d->resp[0] = d->parser.cmd;
    d->resp[1] = get_args_nusers();
    memcpy(d->resp+2,users,strlen(users));
    nwrite = strlen(users) + 2;
    free(users);
    // d->resp = users;
        // d->resp[0] = strlen(user);

        // if()
    return nwrite;
}

static size_t del_user(struct cmd_st *d){
    if(-1 == delete_registered((char*)d->parser.args[0])){
        *d->status = mng_status_nonexisting_user;
    }
    return 0;
}

static size_t change_pass(struct cmd_st *d){
    char * user = (char*)d->parser.args[0];
    char * pass = (char*)d->parser.args[1];
    *d->status = mng_status_succeeded;
    if (-1 == change_user_pass(user,pass)){
        *d->status = mng_status_nonexisting_user;
    }
    return 0;
}

static size_t set_pass_dissector(struct cmd_st *d){
    *d->status = mng_status_succeeded;
    if(d->parser.args[0][0] == 0x00){
        set_args_disectors_enabled(true);
    }
    else if(d->parser.args[0][0] == 0x01){
        set_args_disectors_enabled(false);
    }
    else{
        *d->status = mng_status_malformed_args;
    }
    return 0;
}

static size_t set_doh_ip(struct cmd_st *d){
    *d->status = mng_status_succeeded;
    uint8_t type =  d->parser.args[0][0];
    uint8_t *ans = d->parser.args[1];
    if(type == 0x00){
        char rst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ans, rst, INET_ADDRSTRLEN);
        set_args_doh_ip(rst);
    }
    else if(type == 0x01){
        char rst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ans, rst, INET6_ADDRSTRLEN);
        set_args_doh_ip(rst);
    }   
    else{
        return -1;
    }
    return 0;
}

static size_t set_doh_port(struct cmd_st *d){
    *d->status = mng_status_succeeded;
    uint16_t ans =  d->parser.args[0][0];
    ans = (ans << 8) + d->parser.args[0][1];
    set_args_doh_port(ans);
    printf("new port: %d",get_args_doh_port());
    return 0;
}


static size_t set_doh_host(struct cmd_st *d){
    *d->status = mng_status_succeeded;
    set_args_doh_host((char*)d->parser.args[0]);
    return 0;
}


static size_t set_doh_path(struct cmd_st *d){
    *d->status = mng_status_succeeded;
    set_args_doh_path((char*)d->parser.args[0]);
    return 0;
}
static size_t set_doh_query(struct cmd_st *d){
    *d->status = mng_status_succeeded;
    set_args_doh_query((char*)d->parser.args[0]);
    return 0;
}