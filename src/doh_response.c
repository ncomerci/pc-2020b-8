#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../includes/doh_response.h"


const char * http_version = "HTTP/1.1";
const char * success_code = "200";
const char * header_content = "\r\nCONTENT-";
const char * header_content_type = "TYPE:";
const char * header_content_length = "LENGTH:";
const char * content_type_message = "application/dns-message";
const char * header_end = "\r\n\r\n";

char * doh_response = "HTTP/1.1 200\r\nCONTENT-TYPE:application/dns-message\r\n";



void doh_parser_init(struct auth_parser *p)
{
    p->state = doh_version;
    /* reservo espacio para la estructura de usuario */
    p->usr = malloc(sizeof(*p->usr));
    if(p->usr == NULL){
        p->state = auth_error;
        return;
    }
    /* inicializo las variables */
    p->usr->ulen = 0;
    p->usr->uname = 0; 

    /* reservo espacio para la estructura de usuario */
    p->pass = malloc(sizeof(*p->pass));
    if(p->pass == NULL){
        p->state = auth_error;
        return;
    }
    /* inicializo las variables */
    p->pass->plen = 0;
    p->pass->passwd = 0;  

    p->remaining = 0;
    p->read = 0;
}



// Máquina de Estado para la respuesta HTTP
enum http_state doh_http_parser_feed(http_parser *p, uint8_t b)
{
    switch (p->state) 
    {
 	// me fijo que los primeros bytes coincidan con HTTP/1.1
    case doh_version:

    	printf("version");

    	if (p->read >= strlen(http_version)){
    		if(b == ' '){
    			p->read = 0;
    			p->state = doh_status;
    		} else{
    			p->state = doh_error_version;
            	return p->state;	
    		}
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
       
    case doh_header:

    	/* solo me interesa analizar dos headers: el content-type y el content-length para obtener
    	   el tamaño del body */

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
    	if(header_content_type[p->read++] != b){
    		p->read = 0;
    		p->state = doh_header;
    	}
    	// Leí CONTENT-TYPE: -> chequeo que tengo el contenido correcto ('application/dns-message')
    	if(p->read >= strlen(header_content_type)){
    		p->state = doh_check_content_type;
    	}
    	break;

    case doh_content_lenght_header:
    	if(header_content_length[p->read++] != b){
    		p->read = 0;
    		p->state = doh_header;
    	}
    	// Leí CONTENT-LENGHT: -> me guardo el número en p->content-lenght
    	if(p->read >= strlen(header_content_length)){
    		if(b >= '0' && b <= '9') {
    			p->contentLength = ((p->contentLength * 10) + b ) - '0';
    		} else if(b == '\r'){
    			p->headercounter++;
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
    				p->state = doh_header;
    			} else{
    				p->state = doh_error_content_type_message;
            		return p->state;
    			}
    		}

    	}
    	break;

    default:
    	fprintf(stderr, "unknown state %d\n", p->state);
    	abort();
    	break;

    }

    return p->state;
}



int main(){

	struct http_parser *p;
    p->state = doh_version;
    
    for(int i = 0; i < strlen(doh_response);i++){
    	char b = doh_response[i];
    	uint8_t c;
    	printf("prueba");
    	doh_http_parser_feed(p, c);
    }
   
	//

	printf("%s\n", doh_response );
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



/*

#define DNS_TYPE 2
#define DNS_CLASS 2
#define TTL 4
#define RDLENGTH 2



enum doh_state doh_dns_parser_feed(doh_http_parser *p, uint8_t b)
{
	switch (p->state) 
    {
 	// TODO: comentar
    case doh_dns_request:
	if(p->read < p->dns_request_length){
		p->read ++;
	}
	if(p->read == p->dns_request_length){
		p->state = doh_dns_answer;
	} 
	break;

	case doh_dns_answer:
	if(p->read < p->dns_request_name){
		p->read ++;
	}
	if(p->read >= p->dns_request_name){
		p->state = doh_dns_type;
	} 

    case doh_dns_type:
    // NO ME INTERESA EL TYPE
    p->read ++;
	if(p->read == DNS_TYPE ){
		p->state = doh_dns_class;
	} 
	break;

	case doh_dns_class:
    // NO ME INTERESA LA CLASE
    p->read ++;
	if(p->read == DNS_TYPE ){
		p->state = doh_dns_class;
	} 
	break;

	case doh_dns_ttl:
    // NO ME INTERESA EL TTL
    p->read ++;
	if(p->read == DNS_TYPE ){
		p->state = doh_dns_rlebgth;
	} 
	break;

	
	case doh_dns_rdlength:

	if(p->read < RDLENGTH){
		p->answer[p->anscount].rdlength = ((p->answer[p->anscount].rdlength * 10) + b ) - '0';
		p->read ++; 
	}
	if(p->read == RDLENGTH){
		remaining_set(p, p->answer[p->anscount].rdlength);
		p->answer[p->anscount]->rdata = (uint8_t *)calloc( p->answer[p->anscount].rdlength + 1, sizeof(*p->answer[p->anscount]->rdata));
		if(p->answer[p->anscount]->rdata == NULL)
        {
            p->state = doh_error;
            return p->state;
        }
        p->state = doh_dns_rdata;
    }
    break;

    case doh_dns_rdata:

        *( (p->answer[p->anscount]->rdata) + p->read ) = b; //check if casting is needed "(uint8_t *)"
        p->read++;
    
        if (remaining_is_done(p))
        {
            *( (p->answer[p->anscount]->rdata) + p->read ) = '\0';
            p->state = check_next_answer;
        }
        
        break;


    

	case doh_dns_ttl:
    // NO ME INTERESA EL TYPE
    p->read ++;
	if(p->read == DNS_TYPE ){
		p->state = doh_dns_class;
	} 
	break;




char * doh_response = "HTTP/1.1 200\r\nCONTENT-TYPE:application/dns-message\r\n";

int main(){
	printf("%s\n", doh_response );
}



/*






struct http_response_parser {
    enum http_response_state state;

    uint16_t content_length;    // --> ESTE ME SIRVE PARA TENER EL TAMAÑO DEL BODY
    uint8_t * body;             // ESTA ES LA RESPUESTA DNS -> QUE LE VOY A PASAR AL dns_parser
    uint16_t bytes_read;
    uint16_t bytes_body_begin;
    uint16_t content_length_received;
    uint16_t content_type_received;
    struct dns_parser * dns_parser;
};


*/