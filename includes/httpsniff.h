#ifndef HTTPSNIFF_H
#define HTTPSNIFF_H

#include <stdint.h>
#include <stdbool.h>
#include "logger.h"
#include "selector.h"

#define MAX_SIZE 8192 // aprox max header size
#define N(x) (sizeof(x)/sizeof((x)[0]))

__attribute__((unused)) static const char *http = "HTTP";
__attribute__((unused)) static const char *auth_exp = "Authorization: Basic [A-Za-z0-9+/]+={0,2}";

enum httpsniff_state
{
/*
** Busca 'HTTP' en la primera linea del paquete leyendo hasta /r/n
** TRANSICIONES: HTTP_HEADER | HTTP_DONE
*/
    HTTP_INITIAL,

/*
** Busca 'Authorization: Basic' en el header del paquete
** TRANSICIONES: HTTP_AUTH | HTTP_DONE
*/
    HTTP_HEADER,

/*
** Decodifica user y pass e imprime la info
** TRANSICIONES: HTTP_DONE
*/    
    HTTP_AUTH,

/*
** limpia memoria alocada y vuelve.
*/    
    HTTP_DONE
};

struct http_sniffer {
    /** estado del sniffing */
    enum httpsniff_state status;

    // raw buffer
    uint8_t raw_buff[MAX_SIZE];

    /** info recolectada */
    buffer info;
};

// inicializa la structura
void http_sniff_init(struct http_sniffer *hs);

// maquina de estados
void http_sniff_stm(struct log_info *socks_info, struct http_sniffer *hs, uint8_t *buff, ssize_t n);



#endif 