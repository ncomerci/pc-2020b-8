#ifndef POP3SNIFF_H
#define POP3SNIFF_H

#include <stdint.h>
#include "buffer.h"
#include "logger.h"

#define MAX_SIZE_CRED 255
#define MAX_BUFF_POP3_SIZE 2048

enum pop3sniff_state
{
/*
** Busca '+OK' en la primera linea del paquete leyendo hasta /r/n
** TRANSICIONES: POP3_USER | POP3_DONE
*/
    POP3_INITIAL,

/*
** Busca 'USER'
** TRANSICIONES: POP3_READ_USER | POP3_DONE
*/
    POP3_USER,

/*
** Guarda el nombre de usuario provisto
** TRANSICIONES: POP3_PASS | POP3_DONE
*/
    POP3_READ_USER,

/*
** Busca 'PASS' y guarda la contraseña provista
** TRANSICIONES: POP3_DONE | POP3_READ_PASS
*/    
    POP3_PASS,

/*
** Guarda la contraseña provista
** TRANSICIONES: POP3_DONE | POP3_CHECK
*/    
    POP3_READ_PASS,

/*
** Lee la respuesta del origin para ver si las credenciales son correctas
** en caso de no ser correctas vuelve al estado POP3_USER y descarta 
** la información almacenada. Caso contrario, POP3_SUCCESS y loguea
** TRANSICIONES: POP3_DONE | POP3_USER | POP3_SUCCESS
*/    
    POP3_CHECK,

/*
** Estado si se encontraron credenciales, 
*/    
    POP3_SUCCESS,
/*
** Estado terminal si no se encontraron credenciales, si el parser 
** se encuentra en este estado, no sigue parseando el mensaje
*/    
    POP3_DONE
};

struct pop3_sniffer{
    enum pop3sniff_state state;

    buffer buffer;
    uint8_t raw_buff[MAX_BUFF_POP3_SIZE];
    char username[MAX_SIZE_CRED];
    char password[MAX_SIZE_CRED];
    uint8_t read;
    uint8_t remaining;
    uint8_t check_read;
    uint8_t check_remaining;
    bool parsing;
};

void pop3_sniffer_init(struct pop3_sniffer* sniffer);

enum pop3sniff_state pop3_sniffer_parse(struct pop3_sniffer* s,uint8_t b);

bool pop3_is_done(struct pop3_sniffer *s);

bool pop3_is_parsing(struct pop3_sniffer *s);

enum pop3sniff_state pop3_consume(struct pop3_sniffer *s,struct log_info *log);
#endif