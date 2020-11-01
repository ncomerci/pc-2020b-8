#include "../includes/auth.h"

void auth_parser_init(struct auth_parser *p)
{
    p->state = auth_version;
    memset(p->usr, 0, sizeof(*(p->usr)));
    memset(p->pass, 0, sizeof(*(p->pass)));
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
        if (b == 0x01)
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
            return;
        }

        remaining_set(p, b);
        p->usr->ulen = b;

        //dejamos espacio reservado para el '\0'
        p->usr->uname = (uint8_t *)calloc( p->usr->ulen + 1, sizeof(*p->usr->uname));
        
        //verificamos si se reservó el espacio efectivamente
        if(p->usr->uname == NULL)
        {
            p->state = auth_error;
            return;
        }

        p->state = auth_uname;
        break;
    

    case auth_uname:

        *( (p->usr->uname) + p->read ) = b; //check if casting is needed "(uint8_t *)"
        p->read++;
    
        if (remaining_is_done(p))
        {
            *( (p->usr->uname) + p->read ) = '\0';
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
            return;
        }

        remaining_set(p, b);
        p->pass->plen = b;

        //dejamos espacio reservado para el '\0'
        p->pass->passwd = (uint8_t *)calloc( p->pass->plen + 1, sizeof(*p->pass->passwd));
        
        //verificamos si se reservó el espacio efectivamente
        if(p->pass->passwd == NULL)
        {
            p->state = auth_error;
            return;
        }

        p->state = auth_passwd;
        break;


    case auth_passwd:

        *( (p->pass->passwd) + p->read ) = b; //check if casting is needed "(uint8_t *)"
        p->read++;
    
        if (remaining_is_done(p))
        {
            *( (p->pass->passwd) + p->read ) = '\0';
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


int auth_marshal(buffer *b, const uint8_t status)
{
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if (n < 2)
    {
        return -1;
    }
    buff[0] = 0x01;
    buff[1] = status;
   

    buffer_write_adv(b, 2);
    return 2;
}









