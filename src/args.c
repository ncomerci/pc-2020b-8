#include "../includes/args.h"

struct socks5args *args;

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

static void
user(char *s, struct users *user)
{
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
        user->name = s;
        user->pass = p;
    }
}

static void
version(void)
{
    fprintf(stderr, "socks5v version 1.0\n"
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
            "   -v               Imprime información sobre la versión versión y termina.\n"
            "\n"
            "   --doh-ip    <ip>    Establece la dirección del servidor DoH. Por defecto 127.0.0.1.\n"
            "   --doh-port  <port>  Establece el puerto del servidor DoH. Por defecto 8053.\n"
            "   --doh-host  <host>  Establece el valor del header Host. Por defecto localhost.\n"
            "   --doh-path  <host>  Establece el path del request doh. por defecto /getnsrecord.\n"
            "   --doh-query <host>  Establece el query string si el request DoH utiliza el método Doh por defecto ?dns=.\n"

            "\n",
            progname);
    exit(1);
}

void free_args(){
    free(args);
}

char * get_args_socks_addr(){
    return args->socks_addr;
}

unsigned short get_args_socks_port(){
    return args->socks_port;
}

bool get_args_disectors_enabled(){
    return args->disectors_enabled;
}

int get_args_nusers(){
    return args->nusers;
}
void set_args_nusers(int new_val){
    args->nusers = new_val;
}
struct users* get_args_users(){
    return args->users;
}

char * get_args_doh_ip(){
    return args->doh.ip;
}

void set_args_doh_ip(char * new_ip){
    args->doh.ip = new_ip;
}

char * get_args_doh_host(){
    return args->doh.host;
}

void set_args_doh_host(char * new_host){
    args->doh.host = new_host;
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
    args->doh.path = new_path;
}

char *get_args_doh_query(){
    return args->doh.query;
}
void set_args_doh_query(char * new_query){
    args->doh.query = new_query;
}

int add_new_user(char * user, char * pass){
    if (args->nusers >= MAX_USERS){
        return -1;
    }
    struct users new_user = args->users[args->nusers++];
    new_user.name = user;
    new_user.pass = pass;
    return 1;
}

/* If user deleted was not last in array, 
** move users to reacomodate array
*/
static void shift_users(){

}

// TODO: FINISH
static void delete_user(int i){
    shift_users();
}

int rm_user(char * user){
    for(int i = 0; i < args->nusers; i++){
        if(strcmp(user,args->users[i].name) == 0){
            delete_user(i);
            args->nusers--;
            return 1;
        }
    }
    return -1;
}

void parse_args2(const int argc, char **argv)
{
    // ---------NEW 
    args = (struct socks5args *) malloc(sizeof(*args));
    if(args == NULL){
        fprintf(stderr, "Unable to allocate args struct: ");
        exit(1);
    }
    // ---------- 
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->socks_addr = "0.0.0.0";
    args->socks_port = 1080;

    args->mng_addr = "127.0.0.1";
    args->mng_port = 8080;

    args->disectors_enabled = true;

    args->doh.host = "localhost";
    args->doh.ip = "127.0.0.1";
    args->doh.port = 8053;
    args->doh.path = "/getnsrecord";
    args->doh.query = "?dns=";

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

        c = getopt_long(argc, argv, "hl:L:Np:P:u:v", long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'h':
            usage(argv[0]);
            break;
        case 'l':
            args->socks_addr = optarg;
            break;
        case 'L':
            args->mng_addr = optarg;
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
                exit(1);
            }
            else
            {
                user(optarg, args->users + args->nusers);
                args->nusers++;
            }
            break;
        case 'v':
            version();
            exit(0);
            break;
        case 0xD001:
            args->doh.ip = optarg;
            break;
        case 0xD002:
            args->doh.port = port(optarg);
            break;
        case 0xD003:
            args->doh.host = optarg;
            break;
        case 0xD004:
            args->doh.path = optarg;
            break;
        case 0xD005:
            args->doh.query = optarg;
            break;
        default:
            fprintf(stderr, "unknown argument %d.\n", c);
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
        exit(1);
    }
}

void parse_args(const int argc, char **argv, struct socks5args *args)
{
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->socks_addr = "0.0.0.0";
    args->socks_port = 1080;

    args->mng_addr = "127.0.0.1";
    args->mng_port = 8080;

    args->disectors_enabled = true;

    args->doh.host = "localhost";
    args->doh.ip = "127.0.0.1";
    args->doh.port = 8053;
    args->doh.path = "/getnsrecord";
    args->doh.query = "?dns=";

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

        c = getopt_long(argc, argv, "hl:L:Np:P:u:v", long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'h':
            usage(argv[0]);
            break;
        case 'l':
            args->socks_addr = optarg;
            break;
        case 'L':
            args->mng_addr = optarg;
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
                exit(1);
            }
            else
            {
                user(optarg, args->users + args->nusers);
                args->nusers++;
            }
            break;
        case 'v':
            version();
            exit(0);
            break;
        case 0xD001:
            args->doh.ip = optarg;
            break;
        case 0xD002:
            args->doh.port = port(optarg);
            break;
        case 0xD003:
            args->doh.host = optarg;
            break;
        case 0xD004:
            args->doh.path = optarg;
            break;
        case 0xD005:
            args->doh.query = optarg;
            break;
        default:
            fprintf(stderr, "unknown argument %d.\n", c);
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
        exit(1);
    }
}