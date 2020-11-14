#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../includes/doh_response.h"

const char * http_version = "HTTP";
const char * success_code = "200";
const char * header_content = "\r\nCONTENT-";
const char * header_content_type = "TYPE:";
const char * header_content_length = "LENGTH:";
const char * content_type_message = "application/dns-message";
const char * header_end = "\r\n\r\n";

// char * doh_response = "HTTP/1.0 200 OK\r\nCONTENT-TYPE:application/dns-message\r\nHEADER-PRUEBA:hola\r\nCONTENT-LENGTH:40\r\n\r\n";

// uint8_t dns_response[] = {0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
//                           0x00, 0x00, 0x00, 0x01, 0x06, 0x68, 0x75, 0x6d,
//                           0x61, 0x6e, 0x64, 0x02, 0x69, 0x6f, 0x00, 0x00,
//                           0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00,
//                           0x01, 0x00, 0x00, 0x38, 0x40, 0x00, 0x04, 0xd5,
//                           0xbe, 0x06, 0x42, 0x00, 0x00, 0x29, 0x02, 0x00,
//                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// uint8_t dns_response_answers[] = {0x3f, 0x2b, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 
// 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77, 
// 0x04, 0x69, 0x74, 0x62, 0x61, 0x03, 0x65, 0x64, 
// 0x75, 0x02, 0x61, 0x72, 0x00, 0x00, 0x01, 0x00, 
// 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
// 0x00, 0x00, 0x3c, 0x00, 0x04, 0x12, 0xe5, 0xf3, 
// 0x9f, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
// 0x00, 0x00, 0x3c, 0x00, 0x04, 0x12, 0xe5, 0xb5, 
// 0xac, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 
// 0x00, 0x00, 0x00, 0x00};


static void remaining_set(doh_response *p, uint16_t n)
{
    p->remaining = n;
    p->read = 0;
}


static int remaining_is_done(doh_response *p)
{
    return p->read >= p->remaining;
}



void doh_http_parser_init(struct doh_response *p, size_t length)
{
    memset(p, 0, sizeof(doh_response));
    p->state = doh_version;

    p->request_dns_length = length;
}



// Máquina de Estado para la respuesta HTTP
enum doh_state doh_http_parser_feed(doh_response *p, uint8_t b)
{
    switch (p->state)
    {
        // me fijo que los primeros bytes coincidan con HTTP/1.1
        case doh_version:
            if (p->read >= strlen(http_version)){
                if(b == ' '){
                    p->read = 0;
                    p->state = doh_status;
                } 
                /*
                else{
                    p->state = doh_error_version;
                    return p->state;
                }
                */
            } else if (http_version[p->read++] != b) {
                p->state = doh_error_version;
                return p->state;
            }
            break;
            // me fijo si la respuesta fue exitosa (código 200) -> caso contrario ERROR
        case doh_status:
            if (p->read >= strlen(success_code)){
                if(b == ' '){
                    p->read = 0;
                    p->state = doh_header;
                } else{
                    // después del código 200 tiene que ir un espacio y la palabra OK
                    p->state = doh_error_status;
                    return p->state;
                }
            } else if (success_code[p->read++] != b) {
                p->state = doh_error_status;
                return p->state;
            }
            break;

        /* solo me interesa analizar dos headers: el content-type y el content-length para obtener
              el tamaño del body */
        case doh_header:
            if(tolower(header_content[p->read]) == tolower(b)){
                p->read++;
                if(p->read >= strlen(header_content)){
                    p->read = 0;
                    p->state = doh_content_header;
                }
            } else{
                p->read = 0;
            }
            if(header_end[p->headercounter] == b){
                p->headercounter++;
                if(p->headercounter >= strlen(header_end)){
                    //p->contentLength = 1;
                    //p->contentType = 1;
                    if(p->contentLength != 0 && p->contentType != 0){
                        p->headercounter = 0;
                        p->state = doh_body;
                    } else{
                        p->state = doh_error_header;
                        return p->state;
                    }
                }
            } else{
                p->headercounter = 0;
            }
            break;

            /* me fijo si es content-type o content-lenght analizando el primer byte */


        case doh_content_header:
            if(tolower(b) == 't'){
                p->state = doh_content_type_header;
                p->read++;
            } else if (tolower(b) == 'l'){
                p->state = doh_content_lenght_header;
                p->read++;
            } else{
                p->state = doh_header;
                p->read = 0;
            }
            break;

        case doh_content_type_header:

            if(tolower(header_content_type[p->read++]) != tolower(b)){
                p->read = 0;
                p->state = doh_header;
            }
            // Leí CONTENT-TYPE: -> chequeo que tengo el contenido correcto ('application/dns-message')
            if(p->read >= strlen(header_content_type)){
                p->state = doh_check_content_type;
                p->read = 0;
            }
            break;


        case doh_content_lenght_header:
            if(p->read < strlen(header_content_length)){
                if(tolower(header_content_length[p->read++]) != tolower(b)){
                    p->read = 0;
                    p->state = doh_header;
                }
            } else {
                if(b >= '0' && b <= '9') {
                    p->contentLength = (p->contentLength * 10) + b - '0' ;
                } else if(b == '\r'){
                    p->headercounter++;
                    p->read = 1;
                    p->state = doh_header;
                } else if (b != ' '){
                    p->state = doh_error_content_lenght;
                    return p->state;
                }
            }

            break;

        case doh_check_content_type:
            if(b != ' ' || (p->read > 0 && p->read < strlen(content_type_message))){
                if(p->read < strlen(content_type_message)){
                    if(b != content_type_message[p->read]){
                        p->state = doh_error_content_type_message;
                        return p->state;
                    } else{
                        p->read++;
                    }
                } else{ //caso que read sea mayor o igual a strlen
                    if(b == '\r'){
                        p->read = 1;
                        p->headercounter++;
                        p->contentType = 1;
                        p->state = doh_header;
                    } else{
                        p->state = doh_error_content_type_message;
                        return p->state;
                    }
                }

            }
            break;


        case doh_body:
            p->state = doh_dns_request_start;
            p->read = 0;
            break;


        default:
            abort();
            break;
    }

    return p->state;
}





/*
Chequeo como es una respuesta DNS estándar usando el comando dig -t A y luego corriendo el wireshark.
La misma está constituida por 3 secciones bien diferenciadas:
- HEADER --> igual al header enviado en el request (es exactamente igual al header enviado en doh_request)
- QUERY -->  es exactamente igual a la query enviada en doh_request
- ANSWER --> en esta sección se encuentra la respuesta del servidor
Nos interesa analizar solamente la sección de la respuesta --> Como tenemos la longitud tanto del header como
de la query que enviamos (calculada en doh_request), entonces vamos avanzando el puntero hasta llegar a la
sección de la respuesta. */

/*
ANSWER SECTION (dig -t A www.itba.edu.ar)
- NAME: www.itba.edu.ar (a domain name to which this resource record pertains)
- TYPE: A (two octets that specifies the meaning of the data in the RDATA field)
- CLASS: IN (two octets which specify the class of the data in the RDATA field)
- TTL: 60 (32 bit unsigned integer that specifies the time interval (in seconds) that the resource
record may be cached before it should be discarded)
- RDLENGTH: 4 (an unsigned 16 bit integer that specifies the length in octets of the RDATA field)
- RDATA: 18.229.243.159 (a variable length string of octets that describes the resource. The format of
this information varies according to the TYPE and CLASS of the resource record)
*/



#define RDLENGTH 2
#define DNS_HEADER_START 6 // ID + FLAGS + QUESTIONS
#define DNS_ANCOUNT 2
#define DNS_ANSWER_ATTS 10 // NAME + TYPE + CLASS + TTL
#define DNS_ANSWER_NAME 2
#define DNS_ANSWER_TYPE 2
// #define DNS_ANSWER_CLASS 2
// #define DNS_ANSWER_TTL 4
#define DNS_TYPE_A 1 
#define DNS_TYPE_AAAA 28

static bool is_valid_answer(uint16_t dns_type) {
    return dns_type == DNS_TYPE_A || dns_type == DNS_TYPE_AAAA;
}


enum doh_state doh_dns_parser_feed(doh_response *p, uint8_t b)
{
    switch (p->state)
    {

        // Leo el header hasta el campo que me dice cuantas respuestas tengo
        case doh_dns_request_start:

            if(p->read < DNS_HEADER_START){
                p->read ++;
            }
            if(p->read == DNS_HEADER_START){
                p->state = doh_dns_ancount;
                p->read = 0;
            }

            if(p->aux_request_dns_length++ >= p->request_dns_length){
                p->state = doh_error_request_lenght;
                return p->state;
            }

            /*
            if(p->contentLengthAux++ > p->contentLength){
                p->state = doh_error_body_lenght;
                return p->state;
            }*/

            break;

            // Me guardo en número de respuestas que me devuelve el servidor
        case doh_dns_ancount:

            if(p->read < DNS_ANCOUNT){
                // ( p->answerscounter << 8 ) | b concateno los bytes que me llegan
                p->answerscounter = (p->answerscounter << 8 ) | b;
                p->read++;
            }
            if(p->read == DNS_ANCOUNT){
                p->state = doh_dns_request_end;
                p->read = 0;
                if(p->answerscounter > 0) {
                    p->answers = calloc(p->answerscounter, sizeof(*p->answers));
                }
                else {
                    p->state = doh_response_done;
                }
            }
            if(p->aux_request_dns_length++ >= p->request_dns_length){
                p->state = doh_error_request_lenght;
                return p->state;
            }
              /*
            if(p->contentLengthAux++ > p->contentLength){
                p->state = doh_error_body_lenght;
                return p->state;
            }*/
            break;

            // Termino de leer el header y leo toda la query dns que mande anteriormente
        case doh_dns_request_end:
            if(++p->aux_request_dns_length >= p->request_dns_length){
                p->read = 0;
                p->state = doh_dns_answer_atts;
            }
              /*
            if(p->contentLengthAux++ > p->contentLength){
                p->state = doh_error_body_lenght;
                return p->state;
            }*/
            break;

        case doh_dns_answer_atts:
            p->read++;
            if(p->read == DNS_ANSWER_NAME) {
                p->state = doh_dns_answer_type;
            }
            else if(p->read + 1 >= DNS_ANSWER_ATTS){
                p->read = 0;
                p->state = doh_dns_answer_rdlength;
            }
              /*
            if(p->contentLengthAux++ > p->contentLength){
                p->state = doh_error_body_lenght;
                return p->state;
            }*/
            break;

        case doh_dns_answer_type:
            if(p->read < DNS_ANSWER_NAME + DNS_ANSWER_TYPE) {
                (p->answers + p->anscount_aux)->dns_type = ((p->answers + p->anscount_aux)->dns_type << 8) | b ;
                p->read++;
            }
            else {
                p->state = doh_dns_answer_atts;
            }
            break;

        case doh_dns_answer_rdlength:
            if(p->read < RDLENGTH){
                (p->answers + p->anscount_aux)->rdlength = ((p->answers + p->anscount_aux)->rdlength << 8) | b ;
                p->read++;
            }
            if(p->read == RDLENGTH){
                remaining_set(p, (p->answers + p->anscount_aux)->rdlength);
                if(is_valid_answer((p->answers + p->anscount_aux)->dns_type)) {
                    ((p->answers + p->anscount_aux)->rdata) = (uint8_t *)calloc(((p->answers + p->anscount_aux)->rdlength), sizeof(uint8_t));
                    if((p->answers + p->anscount_aux)->rdata == NULL)
                    {
                        p->state = doh_error;
                        return p->state;
                    }
                    p->state = doh_dns_answer_rdata;
                }
                else {
                    p->state = doh_dns_answer_skip;
                }

                p->read = 0;
            }
              /*
            if(p->contentLengthAux++ > p->contentLength){
                p->state = doh_error_body_lenght;
                return p->state;
            }*/
            break;

        case doh_dns_answer_skip:
            p->read++;
            if (remaining_is_done(p)) {
                if(p->anscount_aux + 1 >= p->answerscounter){
                    p->state = doh_response_done;
                }
                else {
                    p->answerscounter--;
                    p->answers = realloc(p->answers,  p->answerscounter*sizeof(*p->answers));
                    memset(p->answers + p->anscount_aux, 0, sizeof(*p->answers));
                    p->read = 0;
                    p->state = doh_dns_answer_atts;
                }
            }
            break;

        case doh_dns_answer_rdata:
            (p->answers + p->anscount_aux)->rdata[p->read] = b; //check if casting is needed "(uint8_t *)"
            p->read++;

            if (remaining_is_done(p))
            {
                if(p->anscount_aux + 1 >= p->answerscounter){
                    p->state = doh_response_done;
                } else{
                    p->anscount_aux++;
                    p->read = 0;
                    p->state = doh_dns_answer_atts;
                }
            }
            break;
        default:
            abort();
            break;
        }
        return p->state;
    }


enum doh_state doh_consume(buffer *b, size_t req_length, doh_response *p, bool *error) {
    doh_http_parser_init(p, req_length);
    enum doh_state st = p->state;
    bool finished = false;
    while (buffer_can_read(b) && !finished) {
        uint8_t byte = buffer_read(b);
        st = doh_http_parser_feed(p, byte);
        if (doh_is_done(st, error))
        {
            finished = true;
        }
        if(st == doh_body){
            int k = 0;
            p->state = doh_dns_request_start;
            while(buffer_can_read(b) && !finished && k <= p->contentLength){
                uint8_t byte = buffer_read(b);
                st = doh_dns_parser_feed(p, byte);
                if (doh_is_done(st, error)) {
                    finished = true;
                }
                k++;
            }
        }
    }
    return st;
}

bool doh_is_done(const enum doh_state state, bool *error) {
    bool ret = false;
    if (state == doh_error_version || state == doh_error_status || state == doh_error_header ||
        state == doh_error_content_type_message || state == doh_error_content_lenght ||
        state == doh_error_request_lenght || state == doh_error_body_lenght || state == doh_error ) {
        if (error != 0)
        {
            *error = true;
        }
        ret = true;
    }
    else if (state == doh_response_done)
    {
        ret = true;
    }
    return ret;
}