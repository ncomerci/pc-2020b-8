#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../includes/auth.h"

void auth_parser_init(struct auth_parser *p,enum auth_type type)
{
    p->state = auth_version;
    memset(&p->usr, 0, sizeof(p->usr));
    if(&p->usr == NULL){
        p->state = auth_error;
        return;
    }

    memset(&p->pass, 0, sizeof(p->pass));
    if(&p->pass == NULL){
        p->state = auth_error;
        return;
    }

    // Hecho para mantener la escalabilidad en caso de cambios en la version del protocol
    switch (type)
    {
    case AUTH_SOCKS:
        p->version = 0x01;
        break;
    case AUTH_MNG:
        p->version = 0x01;
        break;
    default:
        // Tipo no soportado
        p->state = auth_error;
        break;
    }

    p->remaining = 0;
    p->read = 0;
}


static void remaining_set(auth_parser *p, const int n)
{
    p->remaining = n;
    p->read = 0;
}


static int remaining_is_done(auth_parser *p)
{
    return p->read >= p->remaining;
}


enum auth_state auth_parser_feed(auth_parser *p, uint8_t b)
{
    switch (p->state)
    {
    case auth_version:
        if (b == p->version)
        {
            p->state = auth_ulen;
        }
        else
        {
            p->state = auth_error_unsupported_version;
        }
        break;


    case auth_ulen:

        //verificamos que el username tenga al menos un caracter
        if(b <= 0)
        {
            p->state = auth_error_invalid_ulen;
            return p->state;
        }

        remaining_set(p, b);
        p->usr.ulen = b;

        if(p->usr.uname == NULL)
        {
            p->state = auth_error;
            return p->state;
        }

        p->state = auth_uname;
        break;
    

    case auth_uname:

        *( (p->usr.uname) + p->read ) = b;

        p->read++;
    
        if (remaining_is_done(p))
        {
            *( (p->usr.uname) + p->read ) = '\0';

            p->state = auth_plen;
        }
        else
        {
            p->state = auth_uname;
        }
        break;


    case auth_plen:
        //verificamos que la password tenga al menos un caracter
        if(b <= 0)
        {
            p->state = auth_error_invalid_plen;
            return p->state;
        }

        remaining_set(p, b);
        p->pass.plen = b;

        if(p->pass.passwd == NULL)
        {
            p->state = auth_error;
            return p->state;
        }

        p->state = auth_passwd;
        break;


    case auth_passwd:

        *( (p->pass.passwd) + p->read ) = b;

        p->read++;
    
        if (remaining_is_done(p))
        {
            *( (p->pass.passwd) + p->read ) = '\0';

            p->state = auth_done;
        }
        else
        {
            p->state = auth_passwd;
        }
        break;

    default:
        fprintf(stderr, "unknown state %d\n", p->state);
        abort();
        break;
    }

    return p->state;

}



enum auth_state auth_consume(buffer *b, auth_parser *p, bool *error)
{
    enum auth_state st = p->state;
    bool finished = false;
    while (buffer_can_read(b) && !finished)
    {
        uint8_t byte = buffer_read(b);
        st = auth_parser_feed(p, byte);
        if (auth_is_done(st, error))
        {
            finished = true;
        }
    }
    return st;
}



bool auth_is_done(const enum auth_state state, bool *error)
{
    bool ret = false;
    if (state == auth_error ||
        state == auth_error_unsupported_version ||
        state == auth_error_invalid_ulen ||
        state == auth_error_invalid_plen)
    {
        if (error != 0)
        {
            *error = true;
        }
        ret = true;
    }
    else if (state == auth_done)
    {
        ret = true;
    }
    return ret;
}


int auth_marshal(buffer *b, const uint8_t status, uint8_t version)
{
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if (n < 2)
    {
        return -1;
    }
    buff[0] = version;
    buff[1] = status;
   

    buffer_write_adv(b, 2);
    return 2; 
}


// void auth_parser_close(struct auth_parser *p){
    // free(p->usr);
    // free(p->pass);
// }







