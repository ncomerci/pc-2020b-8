#include "../includes/httpsniff.h"

struct my_regex {
    char *string; 
    int start; 
    int end;
};

static char *get_match(struct my_regex *regex);
static enum httpsniff_state initial_parse(uint8_t *raw_buff, bool *parsing);
static void decoder(char * match, struct log_info *socks_info);

void http_sniff_init(struct http_sniffer *hs) {
    buffer_init(&hs->info, N(hs->raw_buff), hs->raw_buff);
    hs->status = HTTP_INITIAL;
}

void http_sniff_stm(struct log_info *socks_info, struct http_sniffer *hs, uint8_t *buff, ssize_t n) {

    if(hs->status == HTTP_DONE) return;

    size_t size;
    uint8_t *ptr;
    ssize_t aux;

    struct my_regex regex;
    char *match = NULL;

    bool parsing = true;

    ptr = buffer_write_ptr(&hs->info, &size);
    if (n <= (ssize_t) size) {
        aux = n;
    }
    else {
        aux = size;
    }
    memcpy(ptr, buff, aux);
    buffer_write_adv(&hs->info, aux);

    while (parsing)
    {
        switch(hs->status) {
            case HTTP_INITIAL: {
                hs->status = initial_parse(hs->raw_buff, &parsing);
                break;
            }
            case HTTP_HEADER: {
                regex.string = (char *)hs->raw_buff;
                match = get_match(&regex);
                if (match != NULL) {
                    hs->status = HTTP_AUTH;
                }
                else {
                    // longitud de mi data
                    aux = ptr + aux - hs->raw_buff;
                    if(aux >= 4 && strstr((char *)hs->raw_buff + aux - 4, "\r\n\r\n") != NULL) {
                        hs->status = HTTP_DONE;
                    }
                    else {
                        parsing = false;
                    }
                }
                break;
            }
            case HTTP_AUTH: {
                // get and print user and pass
                decoder(match, socks_info);
                hs->status = HTTP_DONE;
                break;
            }
            case HTTP_DONE: {
                buffer_reset(&hs->info);
                free(match);
                parsing = false;
                break;
            }
        }
    }
    
}

static char *get_match(struct my_regex *regex) { 

    int i, w=0, len;                  
    char *word = NULL;
    regex_t rgT;
    regmatch_t match;
    regcomp(&rgT, auth_exp, REG_EXTENDED);

    if ((regexec(&rgT, regex->string, 1, &match, 0)) == 0) {

        regex->start = (int)match.rm_so;
        regex->end = (int)match.rm_eo;
        len = regex->end - regex->start;
        word = malloc(len+1);

        for (i = regex->start; i < regex->end ; i++) {
            word[w] = regex->string[i];
            w++; 
        }

        word[w]='\0';
    }

    regfree(&rgT);
    return word;
}

static enum httpsniff_state initial_parse(uint8_t *raw_buff, bool *parsing) {

    enum httpsniff_state ret = HTTP_DONE;
    int i, j = 0;
    int http_size = strlen(http);

    for(i = 0 ; raw_buff[i] != '\0' && raw_buff[i] != '\n' && j < http_size ; i++) {
        if(raw_buff[i] == http[j]) {
            j++;
        }
        else {
            j = 0;
        }
    }

    if(j == http_size) {
        ret = HTTP_HEADER;
    }
    else if(raw_buff[i] == '\0') {
        ret = HTTP_INITIAL;
        *parsing = false;
    }

    return ret;
}

static void decoder(char * match, struct log_info *socks_info) {

    char *encoded_str = strrchr(match, ' ');
    encoded_str++;

    int decoded_len = Base64decode_len(encoded_str);

    char *decoded_str = malloc(decoded_len);
    Base64decode(decoded_str, encoded_str);

    const char* delim = ":";
    socks_info->user = strtok(decoded_str, delim);
    socks_info->passwd = strtok(NULL, delim);
    socks_info->protocol = HTTP;

    log_sniff(socks_info);
    free(decoded_str); // este free puede traer problemas con el log no bloqueante
}