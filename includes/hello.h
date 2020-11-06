#ifndef HELLO_H
#define HELLO_H
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "buffer.h"

static const uint8_t METHOD_NO_AUTHENTICATION_REQUIRED = 0x00;
static const uint8_t METHOD_NO_ACCEPTABLE_METHODS = 0xFF;
static const uint8_t METHOD_USERNAME_PASSWORD = 0x02;

enum hello_state
{
    hello_version,
    hello_nmethods,
    hello_methods,
    hello_done,
    hello_error_unsupported_version,
};

struct hello_parser
{
    /** invocado cada vez que se presenta un nuevo método **/
    void (*on_authentication_method)(void *data, const uint8_t method);

    /** permite al usuario del parser almacenar sus datos **/
    void *data;

    /********* zona privada *********/
    enum hello_state state;
    /* cantidad de metodos qeu faltan por leer */
    uint8_t remaining;
};

/** inicializa el parser **/
void hello_parser_init(struct hello_parser *p);

/** entrega un byte al parser. Retorna true si se llego al final **/
enum hello_state hello_parser_feed(struct hello_parser *p, uint8_t b);

/** consume los bytes del mensaje del cliente y se los entrega al parser 
 * hasta que se termine de parsear 
**/
enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *error);

/** ensambla la respuesta del hello dentro del buffer con el metodo 
 * seleccionado.
**/
int hello_marshal(buffer *b, const uint8_t method);

bool hello_is_done(const enum hello_state state, bool *error);

void hello_parser_close(struct hello_parser *p);

#endif