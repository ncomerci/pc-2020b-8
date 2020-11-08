/*

Header section format
- ID --> como usamos TCP no es necesario el id --> le asignamos 0x00
a 16 bit identifier assigned by the program that generates any kind of query.
- QR --> 0 en este caso porque es una query
a one bit field that specifies whether this message is a query (0), or a response (1).
- OPCODE --> 0 en este caso porque es una query standard
a four bit field that specifies kind of query in this message.
   0               a standard query (QUERY)

                1               an inverse query (IQUERY)

                2               a server status request (STATUS)

                3-15            reserved for future use
    - AA (Authoritative Answer)
    this bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section.
    - TC (Truncation)
    specifies that this message was truncated due to length greater than that permitted on the transmission channel.
    - RD (Recursion Desired)
    this bit may be set in a query and is copied into the response. If RD is set, it directs the name server to pursue the query recursively.








Question section format
- QNAME -->  www.mydomain.com = 3www8mydomain3com0
represented as a sequence of labels, where each label consists of a length octet followed by that number of octets.
the domain name terminates with the zero length octet for the null label of the root.
no padding is used.
- QTYPE --> A = 0X01 (1) AAAA = 0X1C (28)
a two octet code which specifies the type of the query.
- QCLASS --> IN for the Internet
a two octet code that specifies the class of the query.

*/

#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DNS_QUERY_HEADER 12
#define DNS_QTYPE 2
#define DNS_QCLASS 2

#define DOH_PATH "/dns-query"
#define DOH_QUERY "?dns="



//ENCODER BASE64 URL

char *b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t b64_encoded_size(size_t inlen){
    size_t ret;

    ret = inlen;
    if (inlen % 3 != 0)
        ret += 3 - (inlen % 3);
    ret /= 3;
    ret *= 4;

    return ret;
}

char *b64_encode(const unsigned char *in, size_t len){

    char   *out;
    size_t  elen;
    size_t  i;
    size_t  j;
    size_t  v;

    if (in == NULL || len == 0)
        return NULL;

    elen = b64_encoded_size(len);
    out  = malloc(elen+1);
    out[elen] = '\0';

    for (i=0, j=0; i<len; i+=3, j+=4) {
        v = in[i];
        v = i+1 < len ? v << 8 | in[i+1] : v << 8;
        v = i+2 < len ? v << 8 | in[i+2] : v << 8;

        out[j]   = b64chars[(v >> 18) & 0x3F];
        out[j+1] = b64chars[(v >> 12) & 0x3F];

        if (i+1 < len) {
            out[j+2] = b64chars[(v >> 6) & 0x3F];
        } else {
            out[j+2] = '=';
        }
        if (i+2 < len) {
            out[j+3] = b64chars[v & 0x3F];
        } else {
            out[j+3] = '=';
        }
    }

    return out;
}





/* Función para calcular el QNAME del fqdn */
static uint8_t * getQNAME (uint8_t *fqdn){
    int cant = strlen(fqdn);
    uint8_t new_fqdn_size = cant + 2;
    uint8_t * new_fqdn = malloc(new_fqdn_size * sizeof(uint8_t));
    int pos = 0;
    int i;

    for (i = 0; i < cant;){
        if (fqdn[i] == '.'){
            new_fqdn[pos] = i - pos;
            pos = ++i;
        } else{
            i++;
            new_fqdn[i] = fqdn[i-1];
        }
    }
    new_fqdn[pos] = i - pos;
    new_fqdn[i+1] = 0x00;
//printf("%s\n", new_fqdn);
    return new_fqdn;
}

// type = 0 -> ipv4
// type = 1 -> ipv6
uint8_t * dns_query_generator (uint8_t * fqdn, int type){
    uint8_t query_dns_header[] ={0x00,0x00,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t * dns_query_name = getQNAME(fqdn);
    uint8_t * dns_query = malloc(DNS_QUERY_HEADER + strlen(dns_query_name) + DNS_QTYPE + DNS_QCLASS);

    int request_length = DNS_QUERY_HEADER + strlen(dns_query_name) + 1 + DNS_QTYPE + DNS_QCLASS;

//printf("%s\n", query_dns_header);
    memcpy(dns_query, query_dns_header,DNS_QUERY_HEADER);
// printf("%s\n", dns_query);
    memcpy(dns_query + DNS_QUERY_HEADER, dns_query_name,strlen(dns_query_name));
    int i = DNS_QUERY_HEADER + strlen(dns_query_name) + 1;
    dns_query[i++] = 0x00;
    if (type == 0){
        dns_query[i++] = 0x01;
    } else {
        dns_query[i++] = 0x1C;
    }
    dns_query[i++] = 0x00;
    dns_query[i] = 0x01;

    for( int j = 0 ; j < request_length ; j++){
        printf("%x ",dns_query[j]);
    }

    printf("\n\n");

    char *dns_query_encoded = b64_encode(dns_query,DNS_QUERY_HEADER + strlen(dns_query_name) + 1 + DNS_QTYPE + DNS_QCLASS);
    printf("QUERY ENCODED\n");
    printf("%s\n", dns_query_encoded);

    free(dns_query);


    return (uint8_t *) dns_query_encoded;
}




/*--------------------------------- QUERY DNS OVER HTTP ----------------------------------------------*/

/*
https://support.opendns.com/hc/en-us/articles/360038463251-Querying-OpenDNS-using-DoH-for-developers-

GET :path HTTP/1.0  (where :path = /dns-query?dns=rmUBAAABAAAAAAAAB2NhcmVlcnMHb3BlbmRucwNjb20AAAEAAQ)
Host: wdoh.opendns.com (for example)
Accept: application/dns-message
*/



/* vemos que en el archivo args.h hay una estrutura doh en la cual en el args.c se le
    asigna los valores por default, es decir:
    args->doh.host = "localhost";
    args->doh.path = "/getnsrecord";
    args->doh.query = "?dns=";
    usamos estos valores para formar la query dns sobre http */

uint8_t * http_query_generator(uint8_t * fqdn, int type){


    char * doh_method = "GET ";
    char * doh_path = "/getnsrecord";
    char * doh_query = "?dns=";
    char * dns_query_encoded = dns_query_generator(fqdn, type);
    char * doh_version = " HTTP/1.0\r\n";
    char * doh_host_name = "Host: ";
    char * doh_host = "localhost\r\n";
    char * doh_accept_header = "Accept: application/dns-message\r\n";
//int http_query_length = strlen()
/*

printf("%s\n", doh_method);
printf("%ld\n", strlen(doh_method));*/

    int http_query_length = strlen(doh_method) + strlen(doh_path) + strlen(doh_query) + strlen(dns_query_encoded)
                            + strlen(doh_version) + strlen(doh_host);
    uint8_t * http_query = malloc(http_query_length);



/* The strcat() function appends the src string to the dest string,
       overwriting the terminating null byte ('\0') at the end of dest, and
       then adds a terminating null byte.
--> strcpy escribe el null byte ('\0') al final del string pero luego con strcat lo sobreescribo
    */
    strcpy((char *)http_query, doh_method);
    strcat((char *)http_query, doh_path);
    strcat((char *)http_query, doh_query);
    strcat((char *)http_query, dns_query_encoded);
    strcat((char *)http_query, doh_version);
    strcat((char *)http_query, doh_host_name);
    strcat((char *)http_query, doh_host);
    strcat((char *)http_query, doh_accept_header);


    printf("QUERY que se manda por HTTP\n");
    printf("%s\n", http_query );

    return http_query;



}





int main(){
    uint8_t prueba[] = "www.itba.edu.ar";
    uint8_t * query = http_query_generator (prueba,0);

}
