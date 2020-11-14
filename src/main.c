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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>


#include "../includes/selector.h"
#include "../includes/socks5nio.h"
#include "../includes/args.h"
#include "../includes/stdoutwrite.h"
#include "../includes/mng.h"

#define MAX_PENDING_CONNECTIONS 20

static bool done = false;

static void
sigterm_handler(const int signal)
{
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}


int main(const int argc, char **argv)
{

    // no tenemos nada que leer de stdin
    close(0);

    const char *err_msg = NULL;


    parse_args(argc, argv);
    // parse_args(argc, argv, args);

    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

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

    int server4_fd = -1;
    int server6_fd = -1;

    ///////////////////////////////////////////////////////////// IPv4
    if(get_args_socks_addr4() != NULL) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, get_args_socks_addr4(), &addr.sin_addr);
        addr.sin_port = htons(get_args_socks_port());

        server4_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server4_fd < 0)
        {
            err_msg = "unable to create ipv4 socket";
            goto finally;
        }

        fprintf(stderr, "Listening on IPv4 socks5 server TCP port %d\n", get_args_socks_port());

        // man 7 ip. no importa reportar nada si falla.
        setsockopt(server4_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

        if (bind(server4_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            err_msg = "unable to bind ipv4 socket";
            goto finally;
        }
        //TODO: change MAX PENDING CONNECTIONS
        if (listen(server4_fd, MAX_PENDING_CONNECTIONS) < 0)
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
            err_msg = "setting server ipv4 socket as non-blocking";
            goto finally;
        }

            // registering ipv4 passive socket
        ss = selector_register(selector, server4_fd, &socksv5, OP_READ, NULL);

        if (ss != SELECTOR_SUCCESS)
        {
            err_msg = "registering ipv4 fd";
            goto finally;
        }
    }

    ///////////////////////////////////////////////////////////// IPv6
    if(get_args_socks_addr6() != NULL) {
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        inet_pton(AF_INET6,get_args_socks_addr6(),&addr6.sin6_addr);
        addr6.sin6_port = htons(get_args_socks_port());
        
        server6_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (server6_fd < 0)
        {
            err_msg = "unable to create ipv6 socket";
            goto finally;
        }

        fprintf(stderr, "Listening on IPv6 socks5 server TCP port %d\n", get_args_socks_port());
        setsockopt(server6_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

        if (setsockopt(server6_fd, SOL_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int)) < 0 ) {
            err_msg = "setsockopt(IPV6_V6ONLY) failed";
            goto finally;
        }  

        if (bind(server6_fd, (struct sockaddr *)&addr6,sizeof(addr6)) < 0)
        {
            err_msg = "unable to bind ipv6 socket";
            goto finally;
        }

        if (listen(server6_fd, MAX_PENDING_CONNECTIONS) < 0)
        {
            err_msg = "unable to listen on ipv6 socket";
            goto finally;
        }

        if (selector_fd_set_nio(server6_fd) == -1)
        {
            err_msg = "setting server ipv6 socket as non-blocking";
            goto finally;
        }

        // registering ipv6 passive socket
        ss = selector_register(selector, server6_fd, &socksv5, OP_READ, NULL);

        if (ss != SELECTOR_SUCCESS)
        {
            err_msg = "registering ipv6 fd";
            goto finally;
        }
    }

    ////////////////////////////IPv4 SCTP socket for configuration
    int mng_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP);

    struct sockaddr_in mng_addr;
    mng_addr.sin_family = AF_INET;
    inet_pton(AF_INET,get_args_mng_addr4(),&mng_addr.sin_addr);
    mng_addr.sin_port = htons(get_args_mng_port());

    fprintf(stderr, "Listening on IPv4 configuration SCTP port %d\n", get_args_mng_port());
    setsockopt(mng_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    
    if (bind(mng_fd, (struct sockaddr *)&mng_addr, sizeof(mng_addr)) < 0)
    {
        err_msg = "unable to bind configuration socket";
        goto finally;
    }
    
    //TODO: change MAX PENDING CONNECTIONS
    if (listen(mng_fd, MAX_PENDING_CONNECTIONS) < 0)
    {
        err_msg = "unable to listen on configuration socket";
        goto finally;
    }

    if (selector_fd_set_nio(mng_fd) == -1)
    {
        err_msg = "setting server configuration socket as non-blocking";
        goto finally;
    }

    const struct fd_handler mng_handler = {
        .handle_read = mng_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL, // nada que liberar
    };

    //registering ipv4 configuration passive socket
    ss = selector_register(selector, mng_fd, &mng_handler, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS)
    {
        err_msg = "registering ipv4 mng fd";
        goto finally;
    }

    //registering ipv6 configuration passive socket
    // ss = selector_register(selector, mng_fd6, &mng_handler, OP_READ, NULL);
    // if (ss != SELECTOR_SUCCESS)
    // {
    //     err_msg = "registering ipv6 mng fd";
    //     goto finally;
    // }

    const struct fd_handler stdout_handler = {
        .handle_read = NULL,
        .handle_write = write_handler, // escribe en stdout los bytes que entran en el buffer
        .handle_close = NULL, // nada que liberar
    };

    if(-1 == init_write(selector)){
        err_msg = "Unable to allocate write struct";
        goto finally;
    }
    
    // Setting STDOUT has non blocking
    if (selector_fd_set_nio(1) == -1)
    {
        err_msg = "setting stdout as non-blocking";
        goto finally;
    }

    //register selector for non blockng stdout
    ss = selector_register(selector, 1, &stdout_handler, OP_NOOP, get_write_data());

    if (ss != SELECTOR_SUCCESS)
    {
        err_msg = "registering write fd";
        goto finally;
    }
    

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
    free_write();
    // free args struct
    free_args();

    if (selector != NULL)
    {
        selector_destroy(selector);
    }
    selector_close();
    
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