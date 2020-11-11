#ifndef CMD_H
#define CMD_H
#include <stdint.h>
#include "buffer.h"
#include <stdbool.h>

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
    type_get,
    type_set,
    type_quit,
};

enum cmd{
    cmd_get_transfered,
    cmd_get_historical,
    cmd_get_current,
    cmd_get_users,
    cmd_set_add_user,
    cmd_set_change_pass,
    cmd_set_del_user,
    cmd_set_doh_ip_type,
    cmd_set_doh_ip,
    cmd_set_doh_port,
    cmd_set_doh_host,
    cmd_set_doh_path,
    cmd_set_doh_query,
};

typedef struct cmd_parser{
    enum cmd_state state;
    enum cmd_type type;
    enum cmd cmd;
    uint8_t qargs;


} cmd_parser;


void cmd_parser_init(cmd_parser *parser);

enum cmd_state cmd_consume(buffer *b, cmd_parser *p, bool *error);


#endif