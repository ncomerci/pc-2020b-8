#include "../includes/args.h"
// #define kh_get_val(kname, hash, key, defVal) (khint_t k=kh_get(kname, hash, key);(k!=kh_end(hash)?kh_val(hash,k):defVal);)

struct socks5info *args;

static unsigned short
port(const char *s)
{
    char *end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 || sl > USHRT_MAX)
    {
        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
        exit(1);
        return 1;
    }
    return (unsigned short)sl;
}

// static void user(char *s, struct users *user){
static void user(char *s){

    int absent;
    char *p = strchr(s, ':');
    if (p == NULL)
    {
        fprintf(stderr, "password not found\n");
        exit(1);
    }
    else
    {
        *p = 0;
        p++;
        if(strlen(s) > 255 || strlen(p) > 255){
            fprintf(stderr, "username or password too long, maximum length is 255 characters\n");
            exit(1);
        }
        // memcpy(args->users[0].name,s,strlen(s)+1);
        // memcpy(args->users[0].pass,p,strlen(p)+1);
        char * u = malloc(strlen(s) + 1);
        strcpy(u,s);
        char * ps = malloc(strlen(p) + 1);
        strcpy(ps,p);
        khint_t ku = kh_put(users,args->hu,u,&absent);
        if(absent) {
            khint_t ka = kh_get(admins,args->ha,u);
            if(ka ==kh_end(args->ha)) kh_value(args->hu,ku) = ps;   
        }
        // khint_t ku = kh_put(users,args->hu,args->users[0].name,&absent);
        // if(absent) {
        //     khint_t ka = kh_get(admins,args->ha,s);
        //     if(ka ==kh_end(args->ha)) kh_value(args->hu,ku) = args->users[0].pass;   
        // }
        // strcpy(user->name,s);
        // memcpy(user->name,s,strlen(s))
        // user->name = s;
        // strcpy(user->pass,p);
        // memcpy(user->)
        // user->pass = p;
    }
}

static void
version(void)
{
    fprintf(stderr, "socks5d version 1.0\n"
                    "ITBA Protocolos de Comunicación 2020/2 -- Grupo 8\n"
                    "AQUI VA LA LICENCIA\n");
}

static void
usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
            "   -L <conf  addr>  Dirección donde servirá el servicio de management.\n"
            "   -p <SOCKS port>  Puerto entrante conexiones SOCKS. Por defecto el valor es 1080\n"
            "   -P <conf port>   Puerto entrante conexiones configuracion. Por defecto el valor es 8080\n"
            "   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
            "   -v               Imprime información sobre la versión y termina.\n"
            "\n"
            "   --doh-ip    <ip>    Establece la dirección del servidor DoH. Por defecto 127.0.0.1.\n"
            "   --doh-port  <port>  Establece el puerto del servidor DoH. Por defecto 8053.\n"
            "   --doh-host  <host>  Establece el valor del header Host. Por defecto localhost.\n"
            "   --doh-path  <host>  Establece el path del request doh. por defecto /getnsrecord.\n"
            "   --doh-query <host>  Establece el query string si el request DoH utiliza el método DoH por defecto ?dns=.\n"

            "\n",
            progname);
    exit(1);
}


static void admin(char *s){
    int absent;

    char *p = strchr(s, ':');
    if (p == NULL){
        fprintf(stderr, "password not found\n");
        exit(1);
    }
    else
    {
        *p = 0;
        p++;
        if(strlen(s) > 255 || strlen(p) > 255){
            fprintf(stderr, "username or password too long, maximum length is 255 characters\n");
            exit(1);
        }
        char * u = malloc(strlen(s) + 1);
        strcpy(u,s);
        char * ps = malloc(strlen(p) + 1);
        strcpy(ps,p);
        khint_t ka = kh_put(admins,args->ha,u,&absent);
        if(absent) {
            khint_t ku = kh_get(users,args->hu,u);
            if(ku == kh_end(args->hu)){
                kh_value(args->ha,ka) = ps;   
            } 
        }
    }
}

void free_args(){
    khint_t k;
    for (k = 0; k < kh_end(args->hu); ++k){
        if (kh_exist(args->hu, k)){
            free((char*)kh_val(args->hu,k));
            free((char*)kh_key(args->hu, k));
        }
    }
    for (k = 0; k < kh_end(args->ha); ++k){
        if (kh_exist(args->ha, k)){
            free((char*)kh_val(args->ha,k));
            free((char*)kh_key(args->ha, k));
        }
    }
    kh_destroy(admins, args->ha);
    kh_destroy(users, args->hu);
    free(args);
}

char * get_args_socks_addr4(){
    return args->socks_addr4;
}

char * get_args_socks_addr6(){
    return args->socks_addr6;
}

unsigned short get_args_socks_port(){
    return args->socks_port;
}

bool get_args_disectors_enabled(){
    return args->disectors_enabled;
}

void set_args_disectors_enabled(bool value){
    args->disectors_enabled = value;
}

char * get_args_mng_addr4(){
    return args->mng_addr4;
}

char * get_args_mng_addr6(){
    return args->mng_addr6;
}

unsigned short get_args_mng_port(){
    return args->mng_port;
}

// ************ DOH ************

char * get_args_doh_ip(){
    return args->doh.ip;
}

void set_args_doh_ip(char * new_ip){
    strcpy(args->doh.ip,new_ip);
}

char * get_args_doh_host(){
    return args->doh.host;
}

void set_args_doh_host(char * new_host){
    strcpy(args->doh.host ,new_host);
    strcat(args->doh.host , "\r\n");
}

unsigned short get_args_doh_port(){
    return args->doh.port;
}
void set_args_doh_port(unsigned short new_port){
    args->doh.port = new_port;
}

char * get_args_doh_path(){
    return args->doh.path;
}

void set_args_doh_path(char * new_path){
    strcpy(args->doh.path ,new_path);
}

char *get_args_doh_query(){
    return args->doh.query;
}
void set_args_doh_query(char * new_query){
    strcpy(args->doh.query ,new_query);
}

// ************ USERS/ADMINS ************


int check_admin_credentials(char * user, char * pass){
    khint_t ka = kh_get(admins,args->ha,user);
    
    if(ka != kh_end(args->ha)){
       char* store_pass = kh_val(args->ha,ka);
       if(strcmp(store_pass,pass) == 0) return 1;
    }
    return 0;
}

static int check_user_credentials(char * user, char * pass){
    khint_t ku = kh_get(users,args->hu,user);
    
    if(ku != kh_end(args->hu)){
       char* store_pass = kh_val(args->hu,ku);
       if(strcmp(store_pass,pass) == 0) return 1;
    }
    return 0;
}

int registed(char * user, char * pass){
    return check_admin_credentials(user, pass) || check_user_credentials(user,pass);
}

int get_args_nusers(){
    return args->nusers;
}
void set_args_nusers(int new_val){
    args->nusers = new_val;
}
char * get_all_users(){
    int init = 255;
    khint_t k;
    char * all_users = malloc(255);
    if(all_users == NULL){
        return all_users;
    }
    int cont = 0;
    for (k = 0; k < kh_end(args->hu); ++k){
        if (kh_exist(args->hu, k)){
            char * username = (char *)kh_key(args->hu,k);
            all_users[cont++] = strlen(username);
            strcpy(all_users+cont,username);
            cont += strlen(username);
            if(cont >= init){
                init *= 2;
                if (all_users == realloc(all_users,init)){
                    return NULL;
                }
            }
        }
    }
    return all_users;
}

int get_args_nadmins(){
    return args->nadmins;
}

void set_args_nadmins(int new_val){
    args->nadmins = new_val;
}


int add_new_admin(char * user, char * pass){
    if (args->nadmins >= MAX_USERS){
        return -1;
    }
    int absent; 
    char * u = malloc(strlen(user) + 1);
    strcpy(u,user);
    char * p = malloc(strlen(pass) + 1);
    strcpy(p,pass);
    
    khint_t ka = kh_put(admins,args->ha,u,&absent);
    if(absent) {
        khint_t ku = kh_get(users,args->hu,u);
        if(ku != kh_end(args->hu)) return -2; // Ya existe usuario/admin con ese nombre
        kh_value(args->ha,ka) = p;   
    }
    else{
        return -2; // Ya existe usuario/admin con ese nombre
    }
    args->nadmins ++;
    return 1;    
}   

int add_new_user(char * user, char * pass){
    if (args->nusers >= MAX_USERS){
        return -1;
    }
    int absent;
    char * u = malloc(strlen(user) + 1);
    strcpy(u,user);
    char * p = malloc(strlen(pass) + 1);
    strcpy(p,pass);
    
    khint_t ku = kh_put(users,args->hu,u,&absent);
    if(absent) {
            khint_t ka = kh_get(admins,args->ha,u);
            //TODO delete putted key
            if(ka != kh_end(args->ha)) return -2;
            kh_value(args->hu,ku) = p;   
    }
    else{
        return -2;
    }
    args->nusers++;
    return 1;
}


static int admin_exists(char * user){
    khint_t ka = kh_get(admins,args->ha,user);
    return ka != kh_end(args->ha) ? 1:0;
}

static int user_exists(char * user){
    khint_t ku = kh_get(users,args->hu,user);

    return ku != kh_end(args->hu) ? 1:0;
}


int delete_registered(char * user){
    khint_t k;
    if(admin_exists(user)){
        k = kh_get(admins,args->ha,user);
        free((char*)kh_val(args->ha,k));
        free((char*)kh_key(args->ha, k));
        kh_del(admins,args->ha,k);
        args->nadmins--;
        return 1;
        
    }
    else if(user_exists(user)){
        k = kh_get(users,args->hu,user);
        free((char*)kh_val(args->hu,k));
        free((char*)kh_key(args->hu,k));
        kh_del(users,args->hu,k);
        args->nusers--;
        return 1;
        
    }

    return -1;
}

int change_user_pass(char *user, char *pass){
    khint_t k;
    char* newpass;
    if(admin_exists(user)){
        k = kh_get(admins,args->ha,user);
        free((char*)kh_val(args->ha,k));
        newpass = malloc(strlen(pass)+1);
        strcpy(newpass,pass);
        kh_val(args->ha,k) = newpass;
        return 1;
        // for(int i = 0; i < args->nadmins; i++){
        //     if(strcmp(user,args->admins[i].name) == 0){
        //         strcpy(args->admins[i].pass, pass);
        //         kh_val(args->ha,k) = args->admins[i].pass;
        //         return 1;
        //     }
        // } 
    }
    else if(user_exists(user)){
        k = kh_get(users,args->hu,user);
        free((char*)kh_val(args->hu,k));
        newpass = malloc(strlen(pass)+1);
        strcpy(newpass,pass);
        kh_val(args->hu,k) = newpass;
        return 1;
        // for(int i = 0; i < args->nadmins; i++){
        //     if(strcmp(user,args->users[i].name) == 0){
        //         strcpy(args->users[i].pass, pass);
        //         kh_val(args->ha,k) = args->users[i].pass;
        //         return 1;
        //     }
        // } 
    }
    return -1;
}


// ************ MONITORING ************
uint16_t get_historical_conections(){
    return args->historical_conections;
}

void set_historical_conections(uint16_t amount){
    args->historical_conections = amount;
}

uint16_t get_concurrent_conections(){
    return args->concurrent_conections;
}

void set_concurrent_conections(uint16_t amount){
    args->concurrent_conections = amount;
}


uint32_t get_total_bytes_transfered(){
    return args->total_bytes_transfered;
}

void set_total_bytes_transfered(uint32_t amount){
    args->total_bytes_transfered = amount;
}



void parse_args(const int argc, char **argv)
{
    // ---------NEW 
    args = (struct socks5info *) malloc(sizeof(*args));
    if(args == NULL){
        fprintf(stderr, "Unable to allocate args struct: ");
        exit(1);
    }
    // ---------- 
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->hu = kh_init(users);
    args->ha = kh_init(admins);
    int absent;
    char * uadmin = malloc(6);
    memcpy(uadmin,"admin",6);
    char * padmin = malloc(6);
    memcpy(padmin,"admin",6);
    
    khint_t k = kh_put(admins,args->ha,uadmin,&absent);
    if(absent) kh_value(args->ha,k) = padmin;
    args->nadmins++;

    args->socks_addr6 = "::";
    args->socks_addr4 = "0.0.0.0";
    args->socks_port = 1080;

    args->mng_addr6 = "::1";
    args->mng_addr4 = "127.0.0.1";
    args->mng_port = 8080;

    args->disectors_enabled = true;
    strcpy(args->doh.host,"localhost\r\n");
    strcpy(args->doh.ip,"127.0.0.1");
    args->doh.port = 8053;
    strcpy(args->doh.path,"/getnsrecord");
    strcpy(args->doh.query,"?dns=");


    int c;
    args->nusers = 0;

    while (true)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"doh-ip", required_argument, 0, 0xD001},
            {"doh-port", required_argument, 0, 0xD002},
            {"doh-host", required_argument, 0, 0xD003},
            {"doh-path", required_argument, 0, 0xD004},
            {"doh-query", required_argument, 0, 0xD005},
            {0, 0, 0, 0}};
        struct sockaddr_in sa4;
        struct sockaddr_in6 sa6;
        c = getopt_long(argc, argv, "hl:L:Np:P:u:a:v", long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'h':
            usage(argv[0]);
            break;
        case 'l':
            if(inet_pton(AF_INET, optarg, &(sa4.sin_addr))){
                args->socks_addr4 = optarg;
            }
            else if(inet_pton(AF_INET6, optarg, &(sa6.sin6_addr))){
                args->socks_addr6 = optarg;
            }
            else{
                fprintf(stderr, "Invalid ip address for socks5 proxy.\n");
                free_args();
                exit(1);
            }
            
            break;
        case 'L':
            if(inet_pton(AF_INET, optarg, &(sa4.sin_addr))){
                args->mng_addr4 = optarg;
            }
            else if(inet_pton(AF_INET6, optarg, &(sa6.sin6_addr))){
                args->mng_addr6 = optarg;
            }
            else{
                fprintf(stderr, "Invalid ip address for mng server.\n");
                free_args();
                exit(1);
            }
            break;
        case 'N':
            args->disectors_enabled = false;
            break;
        case 'p':
            args->socks_port = port(optarg);
            break;
        case 'P':
            args->mng_port = port(optarg);
            break;
        case 'u':
            if (args->nusers >= MAX_USERS)
            {
                fprintf(stderr, "maximun number of command line users reached: %d.\n", MAX_USERS);
                free_args();
                exit(1);
            }
            else
            {
                user(optarg);
                args->nusers++;
            }
            break;
        case 'v':
            version();
            exit(0);
            break;
        case 'a':
            admin(optarg);
            args->nadmins++;
            break;
        case 0xD001:
            if(strlen(optarg) > MAX_IP_SIZE){
                fprintf(stderr, "ip too long, max is %d characters\n", MAX_IP_SIZE);
                free_args();
                exit(1);
            }
            strcpy(args->doh.ip, optarg);
            break;
        case 0xD002:
            args->doh.port = port(optarg);
            break;
        case 0xD003:
            if(strlen(optarg) > MAX_CRED_SIZE){
                fprintf(stderr, "host too long, max is %d characters\n", MAX_CRED_SIZE);
                free_args();
                exit(1);
            }
            strcpy(args->doh.host,optarg);
            strcat(args->doh.host,"\r\n");
            break;
        case 0xD004:
            if(strlen(optarg) > MAX_CRED_SIZE){
                fprintf(stderr, "path too long, max is %d characters\n", MAX_CRED_SIZE);
                free_args();
                exit(1);
            }
            strcpy(args->doh.path,optarg);
            break;
        case 0xD005:
            if(strlen(optarg) > MAX_CRED_SIZE){
                fprintf(stderr, "query too long, max is %d characters\n", MAX_CRED_SIZE);
                free_args();
                exit(1);
            }
            strcpy(args->doh.query,optarg);
            break;
        default:
            fprintf(stderr, "unknown argument %d.\n", c);
            free_args();
            exit(1);
        }
    }
    if (optind < argc)
    {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc)
        {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        free_args();
        exit(1);
    }
}
