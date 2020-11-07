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
	- lo primero que quiero determinar es si el estado es igual a 200 -> si no hay un 200 LISTO, cierro la 	   	 conexión
	- podríamos chequear que los primeros bytes sean HTTP
	- para evitar NO tener chunked, lo primero que haría es hacer un request de 1.0 (con 1.0 no vamos a tener 	conexiones persistentes)
	- después buscaría el content-type
IMPORTANTE CHEQUEAR EL ESTADO Y CONTENT-TYPE

*/



enum http_state
{
    doh_version,
    doh_status,
    doh_header,
    doh_content_header,
    doh_content_type_header,
    doh_content_lenght_header,
    doh_check_content_type,
    doh_body,


    // done section
    doh_done,

    // error section
    doh_error_version,
    doh_error_status,
    doh_error_header,
  	doh_error_content_type_message,
  	doh_error_content_lenght,
    
};





typedef struct http_parser{
    enum http_state state;

    int status; //200 caso de éxito, otro caso error
    int contentLength; //tamaño del body -> tamaño de la respuesta DNS
    bool contentType;
	//struct dns_parser *answers; 

	uint8_t headercounter;
	uint8_t answerscounter;
    uint8_t remaining;
    uint8_t read;      
}http_parser;


/* 
Each resource record has the following format:
	- NAME -> 	a domain name to which this resource record pertains.
	- TYPE ->  	two octets containing one of the RR type codes.  This field specifies the meaning of the 				data in the RDATA field.
	- CLASS -> 	two octets which specify the class of the data in the RDATA field.
	- TTL -> 	a 32 bit unsigned integer that specifies the time interval (in seconds) that the resource 				record may be cached before it should be discarded. (0 = no cached)
	- RDLENGTH -> an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
	- RDATA ->	a variable length string of octets that describes the resource.  The format of this 					information varies according to the TYPE and CLASS of the resource record.
*/


/*

struct dns_parser{
    enum dns_state state;

    char *name;        
    uint16_t dnstype;   
    uint16_t dnsclass; 
    uint32_t TTL;       
    uint16_t rdlength;  
    char *rddata;       
};
*/




#endif