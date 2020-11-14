#ifndef CMD_H
#define CMD_H

#include "buffer.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_ARGS 5
#define MAX_ARGS_SIZE 255

// 3. Gets

// 3.1. Pedidos
// +---------+-------+
// |  TYPE   |  CMD  |
// +---------+-------+
// |    1    |   1   | 
// +---------+-------+
// Dónde:
// TYPE se refiere al tipo de comando: ‘0x00’ para GET
// CMD se refiere al comando:
// - ‘0x00’ GET bytes transferidos
// - ‘0x01’ GET conexiones históricas 
// - ‘0x02’ GET conexiones concurrentes 
// - ‘0x03’ GET listar usuarios


// 3.2. Respuestas

// +-----------+-----------+-------------+--------------+
// |  STATUS   |    CMD    |    QARGS    |     ARGS     |
// +-----------+-----------+-------------+--------------+
// |      1    |     1     |      1      |   1 to 255   |
// +-----------+-----------+-------------+--------------+
// 	Dónde:
// STATUS se refiere al estado del pedido:
// - ‘0x00’ Éxito
// - ‘0x01’ Fallo del servidor
// - ‘0x02’ Comando no soportado
// - ‘0x03’ Tipo no soportado
// CMD se refiere al comando solicitado por el cliente:
// - ‘0x00’ GET bytes transferidos (unsigned long big endian)
// - ‘0x01’ GET conexiones históricas (unsigned long big endian)
// - ‘0x02’ GET conexiones concurrentes (unsigned long big endian)
// - ‘0x03’ GET listar usuarios (lista de usuarios codificados en ASCII de 7 bits)
// - QARGS se refiere a la cantidad de argumentos que hay que parsear:
// - ‘0x00’ - ‘0xFF’ (0 - 255)
// ARGS se refiere a los argumentos del comando solicitado dónde el primer byte de cada argumento tiene la longitud del argumento.

// 4. Sets

// 4.1. Pedidos

// +-----------+-----------+-------------+--------------+
// |   TYPE    |    CMD    |    QARGS    |     ARGS     |
// +-----------+-----------+-------------+--------------+
// |     1     |     1     |      1      |   1 to 255   |
// +-----------+-----------+-------------+--------------+
// Dónde:
// TYPE se refiere al tipo de comando: ‘0x01’ para SET
// CMD se refiere al comando:
// - ‘0x00’ SET agregar usuario/admin
//      - Recibe 3 argumentos: tipo usuario y contraseña:
//          - tipo: un byte que nos indica si se quiere agregar usuario o admin
//              - ‘0x00’: admin
//              - ‘0x01’: user
//      - usuario: string ASCII
//      - contraseña: string ASCII
// - ‘0x01’ SET borrar usuario
//      - Recibe 1 argumento: usuario.
//          - usuario: string ASCII
// - ‘0x02’ SET cambiar contraseña de usuario 
//      - Recibe 2 argumentos: usuario y nueva contraseña.
//          - usuario: string ASCII
//          - contraseña: string ASCII
// - ‘0x03’ SET habilitar/deshabilitar el sniffer de contraseñas:
//      - Recibe 1 argumento: prender o apagar
//          - ‘0x00’ prender (1 byte)
//          - ‘0x01’ apagar (1 byte)
// - ‘0x04’ SET DoH IP: permite establecer la dirección del servidor DoH:
//      - Recibe 2 argumento: el tipo de IP y la nueva dirección del servidor DoH 
//          - tipo de ip
//              - ‘0x00’ = IPv4
//              - ‘0x01’ = IPv6
//          - dirección: string ASCII
// - ‘0x05’ SET DoH Port: permite establecer el puerto del servidor DoH:
//      - Recibe 1 argumento: el nuevo puerto del servidor DoH
//          - puerto: 16 bits en big endian
// - ‘0x06’ SET DoH Host: permite establecer el valor del header host:
//      - Recibe 1 argumento: el nuevo valor del header host.
//          - host: string ASCII
// - 0x07’ SET DoH Path: permite establecer el path de la request DoH:
//      - Recibe 1 argumento: el nuevo path del request DoH.
//          - path: string ASCII
// - 0x08’ SET DoH Query: permite establecer el nuevo query string de la request DoH:
//      - Recibe 1 argumento: el nuevo query string de la request DoH.
//          - query: string ASCII
// QARGS se refiere a la cantidad de argumentos que hay que parsear:
//      - ‘0x00’ - ‘0xFF’ (0 - 255)
// ARGS se refiere a los argumentos provistos dónde el primer byte de cada argumento tiene la longitud del argumento y cada argumento se codifica en ASCII de 7 bits
	
// 4.2. Respuestas

// +------------+
// |   STATUS   |
// +------------+
// |     1      |
// +------------+
// Dónde:
// STATUS se refiere al estado del pedido:
// - ‘0x00’ Éxito
// - ‘0x01’ Fallo del servidor
// - ‘0x02’ Comando no soportado
// - ‘0x03’ Tipo no soportado
// - ‘0x04’ Error de argumentos
// - ‘0x05’ Error no existe usuario
// - ‘0x06’ Error no se soportan más usuarios
//  - ‘0x07’ Error nombre de usuario tomado

// 5. Quit
// Al ser orientado a sesión, tenemos que habilitar una manera de cortar la conexión. En una sesión abierta, enviando el primer byte con ‘0x02’, se le indica al servidor que se quiere cerrar la conexión.

// 5.1 Pedido
// +---------+
// |  TYPE   |
// +---------+
// |    1    |
// +---------+
// Dónde:
// TYPE se refiere al tipo de comando: ‘0x02’ para QUIT

// 5.2 Respuesta

// +------------+
// |   STATUS   |
// +------------+
// |     1      |
// +------------+
// Dónde:
// STATUS se refiere al estado del pedido:
// - ‘0x00’ Conexión cerrada exitosamente
// - ‘0x01’ Fallo del servidor
// - ‘0x03’ Tipo no soportado



enum cmd_state{
    cmd_type,
    cmd_cmd,
    cmd_qargs,
    cmd_args,

    // done section
    cmd_done,

    // error section
    cmd_error_unsupported_type,
    cmd_error_unsupported_cmd,
    cmd_error,
    cmd_error_invalid_qargs,
    cmd_error_invalid_args,
};

enum cmd_type{
    type_get = 0x00,
    type_set = 0x01,
    type_quit = 0x02,
};

enum cmd{
    cmd_get_transfered,
    cmd_get_historical,
    cmd_get_concurrent,
    cmd_get_users,
    cmd_set_add_user,
    cmd_set_del_user,
    cmd_set_change_pass,
    cmd_set_pass_dissector,
    cmd_set_doh_ip,
    cmd_set_doh_port,
    cmd_set_doh_host,
    cmd_set_doh_path,
    cmd_set_doh_query,
};


enum cmd_reply_status{
    mng_status_succeeded = 0x00,
    mng_status_general_server_failure = 0x01,
    mng_status_cmd_not_supported = 0x02,
    mng_status_type_not_supported = 0x03,
    mng_status_malformed_args = 0x04,
    mng_status_nonexisting_user = 0x05,
    mng_status_max_users_reached = 0x06,
    mng_status_username_taken = 0x07,
};

typedef struct cmd_parser{ 
    enum cmd_state state;
    enum cmd_type type;
    enum cmd cmd;

    uint8_t args[MAX_ARGS][MAX_ARGS_SIZE];
    enum cmd_reply_status status;
    uint8_t expected_args;
    uint8_t read;
    uint8_t remaining;
    uint8_t arg_len;

} cmd_parser;


void cmd_parser_init(cmd_parser *parser);

/** entrega un byte al parser **/
enum cmd_state cmd_parser_feed(cmd_parser *p, uint8_t b);

enum cmd_state cmd_consume(buffer *b, cmd_parser *p, bool *error);

bool cmd_is_done(const enum cmd_state state, bool *error);

int cmd_marshall(buffer* b, const uint8_t status, uint8_t *resp, size_t nwrite);
#endif