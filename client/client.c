#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>  // socket
#include <arpa/inet.h>
#include <stdbool.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <errno.h>
#include <stdlib.h>
#include <string.h> /* memset */

#define N(x) sizeof(x)/sizeof(x[0])
#define MAX_CRED_SIZE 80

struct user
{
    char *name;
    char *pass;
};

struct mng_args
{

    char *mng_addr;
    unsigned short mng_port;

    struct user user;
};

static void version();
static void usage(const char *progname);
static void user(char *s, struct user *user);
static unsigned short port(const char *s);
void parse_args(const int argc, char **argv,struct mng_args * args);

int main(const int argc, char **argv){

    struct mng_args args;
    parse_args(argc, argv, &args);

    int fd = socket(PF_INET,SOCK_STREAM,IPPROTO_SCTP);

    struct sockaddr_in sv;
    sv.sin_port = htons(args.mng_port);
    sv.sin_family = AF_INET;
    inet_pton(AF_INET,args.mng_addr,&sv.sin_addr);
    uint8_t res[2];
    if(-1 == connect(fd,(struct sockaddr *)&sv,sizeof(sv))){
        perror("couldn't connect");
        return -1;
    }
    // while(1){
    // Si no recibo user/pass pedirlos.
    char user[MAX_CRED_SIZE];
    char pass[MAX_CRED_SIZE];
    if(args.user.name == 0 && args.user.pass == 0){
        printf("Enter username: ");
        scanf("%s",user);
        args.user.name = user;
        printf("Enter password: ");
        scanf(" %s", pass);
        args.user.pass = pass;
    }
    // Create first message
    uint8_t * first_msg = (uint8_t *) malloc(3 + strlen(args.user.name) + strlen(args.user.pass));
    first_msg[0] = 0x01;
    first_msg[1] = strlen(args.user.name);
    strcpy(first_msg + 2,args.user.name);
    first_msg[2 + strlen(args.user.name)] = strlen(args.user.pass);
    strcpy(first_msg + 3 + strlen(args.user.name),args.user.pass);
    // struct msghdr msghdr;
    // struct iovec iov[1];
    // memset(&msghdr,0,sizeof(msghdr));
    // iov[0].iov_base = first_msg;
    // iov[0].iov_len = strlen(args.user.name);
    // msghdr.msg_iov = iov;
    // msghdr.msg_iovlen = 1;
    // ssize_t n;
    // n = sendmsg(fd,&msghdr,MSG_NOSIGNAL);
    // recv(fd,res,2,0);

    send(fd,first_msg,strlen(first_msg),MSG_NOSIGNAL);
    recv(fd,res,2,0);
    //     for(int i = 0; i < 2; i++){
    //         printf("received: %d",res);
    //     }
    //     // send(fd,first_msg,N(first_msg),MSG_NOSIGNAL);

    // // }
    // while(1);

}

void parse_args(const int argc, char **argv,struct mng_args * args){
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users
    args->mng_addr = "127.0.0.1";
    args->mng_port = 8080;
    int c;
    while (true)
    {

        c = getopt(argc, argv, "hL:P:u:v");
        if (c == -1)
            break;

        switch (c)
        {
        case 'h':
            usage(argv[0]);
            exit(1);
            break;
        case 'L':
            args->mng_addr = optarg;
            break;
        case 'P':
            args->mng_port = port(optarg);
            break;
        case 'u':
            user(optarg, &args->user);
            break;
        case 'v':
            version();
            exit(0);
            break;
        default:
            usage(argv[0]);
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

static unsigned short port(const char *s) {
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

static void user(char *s, struct user *user) {
    char *p = strchr(s, ':');
    if (p == NULL || strlen(p) == 1)
    {
        fprintf(stderr, "password not found.\n");
        exit(1);
    }
    else
    {
        *p = 0;
        if(strlen(s) == 0){
            fprintf(stderr, "username not found.\n");
            exit(1);
        }
        p++;
        user->name = s;
        user->pass = p;
    }
}

static void usage(const char *progname){
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -L <conf addr>  Dirección donde servirá el servicio de management. Por defecto utiliza loopback.\n"
            "   -P <conf port>   Puerto entrante conexiones configuracion. Por defecto el valor es 8080\n"
            "   -u <name>:<pass> Usuario y contraseña de usuario para identificarse ante el servidor. Por defecto se pregunta.\n"
            "   -v               Imprime información sobre la versión y termina.\n"
            "\n",
            progname);
}

static void version(){
    fprintf(stderr, "Cliente protocolo G8 version 1.0\n"
                    "ITBA Protocolos de Comunicación 2020/2 -- Grupo 8\n"
                    "AQUI VA LA LICENCIA\n");
}
