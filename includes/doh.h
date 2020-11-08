#ifndef PC_2020B_8_DOH_H
#define PC_2020B_8_DOH_H



size_t b64_encoded_size(size_t inlen);

char *b64_encode(const unsigned char *in, size_t len);

uint8_t * dns_query_generator (uint8_t * fqdn, int type);

/*--------------------------------- QUERY DNS OVER HTTP ----------------------------------------------*/

uint8_t * http_query_generator(uint8_t * fqdn, char * doh_host, char * doh_path, char * doh_query int type);

int doh_request_marshal(buffer *b, uint8_t  * fqdn, struct doh doh_request, int type);

#endif //PC_2020B_8_DOH_H
