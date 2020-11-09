/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de lí­nea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en este hilo.
 *
 * Se descargará en otro hilos las operaciones bloqueantes (resolución de
 * DNS utilizando getaddrinfo), pero toda esa complejidad está oculta en
 * el selector.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>  // socket
#include <sys/socket.h> // socket
#include <netinet/in.h>
#include <netinet/tcp.h>


#include "../includes/selector.h"
#include "../includes/socks5nio.h"
#include "../includes/args.h"
#include "../includes/main.h"
static bool done = false;

static void
sigterm_handler(const int signal)
{
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

struct socks5args* args = NULL;
struct write *write_data = NULL;

struct socks5args* get_args_data(){
    return args;
}
struct write* get_write_data(){
    return write_data;
}
int main(const int argc, char **argv)
{

    // no tenemos nada que leer de stdin
    close(0);

    const char *err_msg = NULL;

    args = (struct socks5args *) malloc(sizeof(*args));
    if(args == NULL){
        err_msg = "unable allocate args struct";
        goto finally;
    }

    parse_args(argc, argv, args);

    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;


    if (selector_fd_set_nio(fileno(stdout)) == -1)
    {
        err_msg = "Non blocking stdout error";
        goto finally;
    }

    ///////////////////////////////////////////////////////////// IPv4
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(args->socks_port);

    const int server4_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server4_fd < 0)
    {
        err_msg = "unable to create ipv4 socket";
        goto finally;
    }

    fprintf(stdout, "Listening on ipv4 TCP port %d\n", args->socks_port);

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server4_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if (bind(server4_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        err_msg = "unable to bind ipv4 socket";
        goto finally;
    }
    //TODO: change MAX PENDING CONNECTIONS
    if (listen(server4_fd, 20) < 0)
    {
        err_msg = "unable to listen on ipv4 socket";
        goto finally;
    }

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    if (selector_fd_set_nio(server4_fd) == -1)
    {
        err_msg = "getting server ipv4 socket flags";
        goto finally;
    }

    ///////////////////////////////////////////////////////////// IPv6
    // TODO: create IPv6 socket
    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_any;
    addr6.sin6_port = htons(args->socks_port);
    
    const int server6_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (server6_fd < 0)
    {
        err_msg = "unable to create ipv6 socket";
        goto finally;
    }

    fprintf(stdout, "Listening on ipv6 TCP port %d\n", args->socks_port);
    // fprintf(stdout, "Listening on ipv6 fd %d\n", server6_fd);

    if (setsockopt(server6_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0 ) {
        err_msg = "setsockopt(SO_REUSEADDR) failed";
        goto finally;
    }

    if (setsockopt(server6_fd, SOL_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int)) < 0 ) {
        err_msg = "setsockopt(IPV6_V6ONLY) failed";
        goto finally;
    }  

    if (bind(server6_fd, (struct sockaddr *)&addr6,sizeof(addr6)) < 0)
    {
        err_msg = "unable to bind ipv6 socket";
        goto finally;
    }

    if (listen(server6_fd, 20) < 0)
    {
        err_msg = "unable to listen on ipv6 socket";
        goto finally;
    }

    if (selector_fd_set_nio(server6_fd) == -1)
    {
        err_msg = "getting server ipv4 socket flags";
        goto finally;
    }

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0,
        },
    };
    if (0 != selector_init(&conf))
    {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if (selector == NULL)
    {
        err_msg = "unable to create selector";
        goto finally;
    }
    const struct fd_handler socksv5 = {
        .handle_read = socksv5_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL, // nada que liberar
    };

    // registering ipv4 passive socket
    ss = selector_register(selector, server4_fd, &socksv5, OP_READ, NULL);

    if (ss != SELECTOR_SUCCESS)
    {
        err_msg = "registering ipv4 fd";
        goto finally;
    }

    // registering ipv6 passive socket
    ss = selector_register(selector, server6_fd, &socksv5, OP_READ, NULL);

    if (ss != SELECTOR_SUCCESS)
    {
        err_msg = "registering ipv6 fd";
        goto finally;
    }

    const struct fd_handler stdout_handler = {
        .handle_read = NULL,
        .handle_write = write_handler, // escribe en stdout los bytes que entran en el buffer
        .handle_close = NULL, // nada que liberar
    };
    // struct write** aux = get_write();
    // struct write* write = *aux;
    write_data = malloc(sizeof(*write_data));

    if(write_data == NULL){
        err_msg = "Unable to allocate write struct";
        goto finally;
    }
    write_data->selector = selector;
    buffer_init(&write_data->wb, N(write_data->raw_buff), write_data->raw_buff);

    ss = selector_register(selector, 1, &stdout_handler, OP_NOOP, write_data);

    if (ss != SELECTOR_SUCCESS)
    {
        err_msg = "registering write fd";
        goto finally;
    }
    //register selector for non blockng stdout

    for (; !done;)
    {
        err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS)
        {
            err_msg = "serving";
            goto finally;
        }
    }
    if (err_msg == NULL)
    {
        err_msg = "closing";
    }

    int ret = 0;

finally:
    if (ss != SELECTOR_SUCCESS)
    {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
                ss == SELECTOR_IO
                    ? strerror(errno)
                    : selector_error(ss));
        ret = 2;
    }
    else if (err_msg)
    {
        perror(err_msg);
        ret = 1;
    }
    // free write struct
    if(write_data != NULL){
        free(write_data);
    }
    
    // free args struct
    if(args != NULL){
        free(args);
    }

    if (selector != NULL)
    {
        selector_destroy(selector);
    }
    selector_close();

    socksv5_pool_destroy();
    
    if (server4_fd >= 0)
    {
        close(server4_fd);
    }

    if (server6_fd >= 0)
    {
        close(server6_fd);
    }
    return ret;
}