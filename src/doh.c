#include "../includes/doh.h"

#include <math.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DNS_QUERY_HEADER 12
#define DNS_QTYPE 2
#define DNS_QCLASS 2

#define ipv4_to_long(x) ((x[3]<<24) | (x[2]<<16)| (x[1]<<8) | x[0])

static char *host = "localhost\r\n";
static char *ip = "127.0.0.1";
static char *path = "/dns-query"; //TODO: cambiar a getnsrecord antes de entregar
static char *query = "?dns=";
static size_t port = 8053;

static void doh_init(struct DoH *doh);
static void doh_close(struct selector_key *key);
static void doh_done(struct selector_key *key);
static void doh_write(struct selector_key *key);
static void doh_read(struct selector_key *key);
static void save_results(struct doh_response *dr, struct addr_resolv *addr_r, bool *error);

const struct fd_handler doh_handler = {
    .handle_read = doh_read,
    .handle_write = doh_write,
    .handle_close = doh_close,
};

static void doh_init(struct DoH *doh) {

    memset(doh->raw_buff, 0, MAX_BUFF_SIZE);
    buffer_init(&doh->buff, MAX_BUFF_SIZE, doh->raw_buff);
    doh->host = host;
    doh->ip = ip;
    doh->port = port;
    doh->path = path;
    doh->query = query;
    doh->fqdn = NULL;
}

static void doh_close(struct selector_key *key) {
    free(DOH_ATTACH(key));
}

static void doh_done(struct selector_key *key) {

    const int fd = DOH_ATTACH(key)->doh_fd;

    if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fd))
    {
        abort();
    }
    // TODO: funcion que libera answers
    close(fd);

}

static void doh_write(struct selector_key *key) {
    int error;
    socklen_t len = sizeof(error);
    struct DoH * doh = DOH_ATTACH(key);

    if(getsockopt(doh->doh_fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
        
        if (error != 0)
        {
            goto fail;
        }
        else {
            size_t count;
            doh_request_marshal(doh, IPv4);

            uint8_t * ptr = buffer_read_ptr(&doh->buff, &count);
            ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);
            if (n == -1)
            {
                goto fail;
            }
            buffer_read_adv(&doh->buff, n);
            if (!buffer_can_read(&doh->buff)) {
                selector_status st = selector_set_interest_key(key, OP_READ);
                
                if (st != SELECTOR_SUCCESS) {
                    goto fail;
                }
                
            }
        }
    }

    return;

fail:
    selector_set_interest(key->s, doh->client_fd, OP_WRITE);
    doh_done(key);
}

static void doh_read(struct selector_key *key) {

    struct DoH * doh = DOH_ATTACH(key);

    uint8_t *ptr;
    size_t count;
    ssize_t n;
    bool error;
    struct doh_response dr;

    ptr = buffer_write_ptr(&doh->buff, &count);
    n = recv(doh->doh_fd, ptr, count, 0);

    if(n > 0) {
        buffer_write_adv(&doh->buff, n);

        enum doh_state st = doh_consume(&doh->buff, doh->req_length, &dr, &error);

        if(doh_is_done(st, &error)) {
            selector_status st = selector_set_interest(key->s, doh->client_fd, OP_WRITE);
            if (st != SELECTOR_SUCCESS) {
                goto fail;
            }

            save_results(&dr, doh->ar, &error);
            if(error) {
                goto fail;
            }

            doh_done(key);
        }
        else {
            goto fail;
        }
    }
    else {
        goto fail;
    }

    return;

fail:

    selector_set_interest(key->s, doh->client_fd, OP_WRITE);
    // TODO: free de rdatas y answers
    doh_done(key);
}

static void save_results(struct doh_response *dr, struct addr_resolv *addr_r, bool *error) {
    addr_r->cant_addr = dr->answerscounter;
    struct dns_parser *answers = dr->answers;

    addr_r->origin_addr_res = malloc(addr_r->cant_addr * sizeof(struct sockaddr_storage));

    if(addr_r->origin_addr_res == NULL) {
        *error = true;
        return;
    }

    for(size_t i = 0 ; i < addr_r->cant_addr ; i++) {
        if(answers[i].rdlength == IPV4_LEN) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(struct sockaddr_in));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = ipv4_to_long(answers[i].rdata);
            memcpy(&addr_r->origin_addr_res[i], (struct sockaddr_storage *)&addr, sizeof(addr));
        }
        else if(answers[i].rdlength == IPV6_LEN) {
            struct sockaddr_in6 addr;
            memset(&addr, 0, sizeof(struct sockaddr_in6));
            addr.sin6_family = AF_INET6;
            memcpy(addr.sin6_addr.__in6_u.__u6_addr8, answers[i].rdata, IPV6_LEN);
            memcpy(&addr_r->origin_addr_res[i], (struct sockaddr_storage *)&addr, sizeof(addr));
        }
    }
}


int create_doh_request(fd_selector s, char *fqdn, int client_fd, struct addr_resolv * ar) {

    struct DoH* doh = malloc(sizeof(struct DoH));

    if(doh == NULL) {
        goto fail;
    }

    doh_init(doh);
    doh->fqdn = fqdn;
    doh->ar = ar;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1){
        goto fail;
    }

    if (selector_fd_set_nio(fd) == -1)
    {
        goto fail;
    }

    doh->doh_fd = fd;
    doh->client_fd = client_fd;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(doh->port);
    
    if(inet_pton(addr.sin_family, doh->ip, &addr.sin_addr) <= 0)
    {
        goto fail;
    } 

    if(connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) == -1) 
    {
        if (errno == EINPROGRESS)
        {
            // hay que esperar a la conexión

            // // dejamos de pollear el socket del cliente
            // selector_status st = selector_set_interest_key(key, OP_NOOP);
            // if (st != SELECTOR_SUCCESS)
            // {
            //     goto fail;
            // }

            // esperamos la conexión en el nuevo socket
            selector_status st = selector_register(s, fd, &doh_handler, OP_WRITE, doh);
            if (st != SELECTOR_SUCCESS)
            {
                goto fail;
            }
        }
        else {
            goto fail; 
        }
    }

    return 0;

fail:
    free(doh);
    return -1;
}

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

//ENCODER BASE64 URL

// char *b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// size_t b64_encoded_size(size_t inlen){
//     size_t ret;

//     ret = inlen;
//     if (inlen % 3 != 0)
//         ret += 3 - (inlen % 3);
//     ret /= 3;
//     ret *= 4;

//     return ret;
// }

// char *b64_encode(const char *in, size_t len){

//     char   *out;
//     size_t  elen;
//     size_t  i;
//     size_t  j;
//     size_t  v;

//     if (in == NULL || len == 0)
//         return NULL;

//     elen = b64_encoded_size(len);
//     out  = malloc(elen+1);
//     out[elen] = '\0';

//     for (i=0, j=0; i<len; i+=3, j+=4) {
//         v = in[i];
//         v = i+1 < len ? v << 8 | in[i+1] : v << 8;
//         v = i+2 < len ? v << 8 | in[i+2] : v << 8;

//         out[j]   = b64chars[(v >> 18) & 0x3F];
//         out[j+1] = b64chars[(v >> 12) & 0x3F];

//         if (i+1 < len) {
//             out[j+2] = b64chars[(v >> 6) & 0x3F];
//         } else {
//             out[j+2] = '=';
//         }
//         if (i+2 < len) {
//             out[j+3] = b64chars[v & 0x3F];
//         } else {
//             out[j+3] = '=';
//         }
//     }

//     return out;
// }





/* Función para calcular el QNAME del fqdn */
char * getQNAME (char *fqdn){
    int cant = strlen(fqdn);
    size_t new_fqdn_size = cant + 2;
    char * new_fqdn = malloc(new_fqdn_size * sizeof(char) + 1);
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
    new_fqdn[new_fqdn_size] = 0x00;
//printf("%s\n", new_fqdn);
    return new_fqdn;
}

char * dns_query_generator(char *fqdn, ip_type type, size_t *req_length){
    uint8_t query_dns_header[] ={0x00,0x00,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00};
    char * dns_query_name = getQNAME(fqdn);
    size_t dns_query_name_len = strlen(dns_query_name) + 1;

    *req_length = DNS_QUERY_HEADER + dns_query_name_len + DNS_QTYPE + DNS_QCLASS;

    uint8_t *dns_query = malloc(*req_length * sizeof(uint8_t) + 1);


//printf("%s\n", query_dns_header);
    memcpy(dns_query, query_dns_header,DNS_QUERY_HEADER);
// printf("%s\n", dns_query);
    memcpy(dns_query + DNS_QUERY_HEADER, dns_query_name, dns_query_name_len);
    int i = DNS_QUERY_HEADER + dns_query_name_len;
    dns_query[i++] = 0x00;

    if (type == IPv4){
        dns_query[i++] = 0x01;
    } else if(type == IPv6) {
        dns_query[i++] = 0x1C;
    }
    else {
        dns_query[i++] = 0xFF;
    }
    dns_query[i++] = 0x00;
    dns_query[i] = 0x01;
    dns_query[*req_length] = 0x00; //cero final

    int encode_len = Base64encode_len(*req_length);

    char *dns_query_encoded = malloc(encode_len + 1);
    Base64encode(dns_query_encoded, dns_query, *req_length);

    free(dns_query);
    free(dns_query_name);

    return dns_query_encoded;
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

uint8_t * http_query_generator(struct DoH *doh, ip_type type){

    // Constantes que vamos a usar para armar el request
    char * doh_method = "GET ";
    char * doh_version = " HTTP/1.0\r\n";
    char * doh_host_name = "Host: ";
    char * doh_accept_header = "Accept: application/dns-message\r\n\r\n";

    // Creo el request DNS y lo guardo en la variable dns_query_encoded
    char * dns_query_encoded = dns_query_generator(doh->fqdn, type, &doh->req_length);
    // Calculo la longitud total del request DoH
    int http_query_length = strlen(doh_method) + strlen(doh->path) + strlen(doh->query) + strlen(dns_query_encoded) +
                            strlen(doh_version) + strlen(doh_host_name) + strlen(doh->host) + strlen(doh_accept_header) + 1;
    
/* The strcat() function appends the src string to the dest string,
       overwriting the terminating null byte ('\0') at the end of dest, and
       then adds a terminating null byte.
--> strcpy escribe el null byte ('\0') al final del string pero luego con strcat lo sobreescribo
    */
    uint8_t * http_query = malloc(http_query_length + 1);

    strcpy((char *)http_query, doh_method);
    strcat((char *)http_query, doh->path);
    strcat((char *)http_query, doh->query);
    strcat((char *)http_query, dns_query_encoded);
    strcat((char *)http_query, doh_version);
    strcat((char *)http_query, doh_host_name);
    strcat((char *)http_query, doh->host);
    strcat((char *)http_query, doh_accept_header);

    /* Usado para testear que todo se este mandando correctamente
    printf("QUERY que se manda por HTTP\n");
    printf("%s\n", http_query ); */

    free(dns_query_encoded);
    return http_query;
}


int doh_request_marshal(struct DoH *doh, ip_type type) {

    size_t n;
    uint8_t *buff = buffer_write_ptr(&doh->buff, &n);
    uint8_t * doh_request = http_query_generator(doh, type);
    size_t doh_request_length = strlen((char *)doh_request);
    if (n < doh_request_length)
    {
        return -1;
    }
    strcpy((char *)buff, (char *)doh_request);
    buffer_write_adv(&doh->buff, doh_request_length);
    free(doh_request);

    return doh_request_length;
}



/* Usado para testear que este imprimiendo bien 

int main(){
    uint8_t prueba[] = "www.itba.edu.ar";
    uint8_t * query = http_query_generator (prueba,0);
} */

                