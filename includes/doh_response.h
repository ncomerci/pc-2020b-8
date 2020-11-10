#ifndef DOH_RESPONSE_H
#define DOH_RESPONSE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "buffer.h"


/*
HTTP Response Example
:status = 200
   content-type = application/dns-message
   content-length = 61
   cache-control = max-age=3709

PARSER HTTP: parsea la respuesta HTTP
- lo primero que quiero determinar es si el estado es igual a 200 -> si no hay un 200 LISTO, cierro la   conexión
- podríamos chequear que los primeros bytes sean HTTP
- para evitar NO tener chunked, lo primero que haría es hacer un request de 1.0 (con 1.0 no vamos a tener conexiones persistentes)
- después buscaría el content-type
IMPORTANTE CHEQUEAR EL ESTADO Y CONTENT-TYPE

*/



enum doh_state
{
    // estados para el doh header
    doh_version,
    doh_status,
    doh_header,
    doh_content_header,
    doh_content_type_header,
    doh_content_lenght_header,
    doh_check_content_type,
    doh_body,

    // errores para el doh header
    doh_error_version,
    doh_error_status,
    doh_error_header,
    doh_error_content_type_message,
    doh_error_content_lenght,

    // estados para el doh body
    doh_dns_request_start,
    doh_dns_ancount,
    doh_dns_request_end,
    doh_dns_answer_atts,
    doh_dns_answer_rdlength,
    doh_dns_answer_rdata,


    // done section
    doh_response_done,

    // errores para el doh body
    doh_error_request_lenght,
    doh_error_body_lenght,
    doh_error,
};



typedef struct doh_response {
    enum doh_state state;

    int status; //200 caso de éxito, otro caso error
    uint16_t  contentLength; //tamaño del body -> tamaño de la respuesta DNS
    int contentType;
    int anscount_aux;
    struct dns_parser * answers;
    size_t request_dns_length;
    size_t aux_request_dns_length;

    uint8_t headercounter;
    uint16_t answerscounter;
    uint16_t remaining;
    uint8_t read;
}doh_response;


/*
Each resource record has the following format:
- NAME -> a domain name to which this resource record pertains.
- TYPE ->   two octets containing one of the RR type codes.  This field specifies the meaning of the data in the RDATA field.
- CLASS -> two octets which specify the class of the data in the RDATA field.
- TTL -> a 32 bit unsigned integer that specifies the time interval (in seconds) that the resource record may be cached before it should be discarded. (0 = no cached)
- RDLENGTH -> an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
- RDATA -> a variable length string of octets that describes the resource.  The format of this information varies according to the TYPE and CLASS of the resource record.
*/




struct dns_parser{
    uint16_t rdlength;
    uint8_t * rdata;
};




void doh_http_parser_init(struct doh_response *p, size_t length);

enum doh_state doh_http_parser_feed(doh_response *p, uint8_t b);

enum doh_state doh_dns_parser_feed(doh_response *p, uint8_t b);

enum doh_state doh_consume(buffer *b, size_t req_length, doh_response *p, bool *error);

bool doh_is_done(const enum doh_state state, bool *error);




#endif