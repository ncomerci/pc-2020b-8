#ifndef httpsniff_H
#define httpsniff_H

#include "buffer.h"

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
** limpia memoria alocada y vuelve 
** TRANSICIONES: COPY
*/    
    HTTP_DONE
};

struct http_sniffer {
    /** estado del sniffing */
    enum httpsniff_state status;

    /** info recolectada */
    buffer info;
};

// inicializa la structura
void http_sniff_init(struct http_sniffer *hs);

// maquina de estados
void http_sniff_stm(struct http_sniffer *hs);



#endif 