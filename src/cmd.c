#include "../includes/cmd.h"
#define GETCMDS 4
#define SETCMDS 9
uint8_t get_cmds[] = {cmd_get_transfered, cmd_get_historical, cmd_get_concurrent, cmd_get_users};
uint8_t set_cmds[][2] = {{cmd_set_add_user,2}, {cmd_set_del_user,1}, {cmd_set_change_pass,2}, {cmd_set_pass_dissector,1},
                        {cmd_set_doh_ip,1}, {cmd_set_doh_port,1}, {cmd_set_doh_host,1}, {cmd_set_doh_path,1},
                        {cmd_set_doh_query,1}};

void cmd_parser_init(cmd_parser *p){
    memset(p,0,sizeof(*p));
    p->remaining = 0;
    p->read = 0;
    p->state = cmd_type;
}

static enum cmd_state type(cmd_parser *p, uint8_t b){
    enum cmd_state ret = cmd_cmd;
    if(b >= 0 || b <= 2){
        p->type = b;
        if(b == 2){
            p->status = mng_status_succeeded;
            ret = cmd_done;
        }
    }
    else{
        ret = cmd_error_unsupported_type;
    }
    return ret;
}

static enum cmd_state cmd(cmd_parser *p, uint8_t b){
    enum cmd_state ret;
    if(p->type == 0x00 && (b >= 0 || b < GETCMDS)){
        p->cmd = get_cmds[b];
        ret = cmd_done;
        p->status = mng_status_succeeded;
    }
    else if(p->type == 0x01 && (b >= 0 || b < SETCMDS)){
        p->cmd = set_cmds[b][0];
        p->expected_args = set_cmds[b][1];
        ret = cmd_qargs;
    }
    else{
        p->status = mng_status_cmd_not_supported;
        ret = cmd_error_unsupported_cmd;
    }
    return ret;
}

static enum cmd_state qargs(cmd_parser *p, uint8_t b){
    enum cmd_state ret = cmd_args;
    if(b > 0 && p->expected_args == b){
        p->remaining = b;
        p->read = 0;
        p->arg_len = 0;
    }
    else
    {
        p->status = mng_status_malformed_args;
        ret = cmd_error_invalid_qargs;
    }
    return ret;
}

static enum cmd_state args(cmd_parser *p, uint8_t b){
    enum cmd_state ret = cmd_args;
    uint8_t curr = p->expected_args - p->remaining;
    if(p->arg_len - p->read == 0){
        p->read = 0;
        p->arg_len = b;
        if(p->arg_len == 0){
            p->status = mng_status_malformed_args;
            ret = cmd_error_invalid_args;
        }   
        return ret;
    }
    if(p->read < (MAX_ARGS_SIZE -  1)){
        p->args[curr][p->read++] = b;
        if(p->arg_len - p->read == 0){
            p->args[curr][p->read] = 0;
            p->remaining--;
            if(p->remaining == 0){
                p->status = mng_status_succeeded;
                ret = cmd_done;
            }
        }
    }
    else{
        p->status = mng_status_malformed_args;
        ret = cmd_error_invalid_args;
    }
    return ret;
}

enum cmd_state cmd_parser_feed(cmd_parser *p, uint8_t b){
    switch (p->state){
    case cmd_type:
        p->state = type(p,b);
        break;
    case cmd_cmd:
        p->state = cmd(p,b);
        break;
    case cmd_qargs:
        p->state = qargs(p,b);
        break;
    case cmd_args:
        p->state = args(p,b);
        break;

    // done section
    case cmd_done:
        break;

    // error section
    case cmd_error_unsupported_type:
        break;
    case cmd_error_unsupported_cmd:
        break;
    case cmd_error:
        break;
    case cmd_error_invalid_qargs:
        break;
    case cmd_error_invalid_args:
        break;
    default:
        break;
    }
    return p->state;
}


enum cmd_state cmd_consume(buffer *b, cmd_parser *p, bool *error){
    enum cmd_state st = p->state;
    bool finished = false;
    while (buffer_can_read(b) && !finished)
    {
        uint8_t byte = buffer_read(b);
        st = cmd_parser_feed(p, byte);
        if (cmd_is_done(st, error))
        {
            finished = true;
        }
    }
    return st;
}

bool cmd_is_done(const enum cmd_state state, bool *error){
    bool ret = false;
    if (state == cmd_error ||
        state == cmd_error_unsupported_type ||
        state == cmd_error_unsupported_cmd ||
        state == cmd_error_invalid_qargs ||
        state == cmd_error_invalid_args)
    {
        if (error != 0)
        {
            *error = true;
        }
        ret = true;
    }
    else if (state == cmd_done)
    {
        ret = true;
    }
    return ret;
}

int cmd_marshall(buffer* b, const uint8_t status, uint8_t *resp, size_t nwrite){
    size_t count;
    uint8_t * ptr = buffer_write_ptr(b,&count);
    if(count < nwrite + 1){
        return -1;
    }
    ptr[0] = status;
    buffer_write_adv(b,1);
    if(nwrite > 0){
        memcpy(ptr+1,resp,nwrite);
        buffer_write_adv(b,nwrite);
        free(resp);
    }
    return nwrite;
}