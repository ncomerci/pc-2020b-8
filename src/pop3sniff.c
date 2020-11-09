#include "../includes/pop3sniff.h"
#define INITIAL_SIZE 50
#define N(x) (sizeof(x)/sizeof((x)[0]))

static const char * OK = "+OK";
static const char * USER = "USER ";
static const char * PASS = "PASS ";
static const char * QUIT = "QUIT";
static const char * ERR = "-ERR";

static void reset_counters(struct pop3_sniffer* s, uint8_t left){
    s->read = 0;
    s->remaining = left;
}

void pop3_sniffer_init(struct pop3_sniffer* sniffer){
    sniffer->state = POP3_INITIAL;
    memset(sniffer->raw_buff,0,MAX_BUFF_SIZE);
    buffer_init(&sniffer->buffer, N(sniffer->raw_buff), sniffer->raw_buff);
    sniffer->read = 0;
    sniffer->remaining = strlen(OK);
    sniffer->parsing = true;
}

static enum pop3sniff_state initial_msg(struct pop3_sniffer* s,uint8_t b){
    enum pop3sniff_state st = POP3_INITIAL;
    if(tolower(b) == tolower(*(OK + s->read))){
        s->read++;
        s->remaining--;
        if(s->remaining == 0){
            st = POP3_USER;
            s->read = 0;
            s->remaining = strlen(USER);
        }
    }
    else{
        st = POP3_DONE;
    }
    return st;
}

enum pop3sniff_state keyword(struct pop3_sniffer* s,uint8_t b, const char * keyword,enum pop3sniff_state initial_state, enum pop3sniff_state goto_state){
    enum pop3sniff_state st = initial_state;
    if(tolower(b) == tolower(*(keyword + s->read))){
        s->read++;
        s->remaining--;
        if(s->remaining == 0){
            s->read = 0;
            st = goto_state;
        }        
    }
    else{
        if(s->read != 0){
            reset_counters(s,strlen(keyword));
        }
    } 
    return st;
}

enum pop3sniff_state read_user(struct pop3_sniffer* s,uint8_t b){
    enum pop3sniff_state st = POP3_READ_USER;
    if(b != '\n'){
        // No leemos los espacios
        if(s->read < MAX_SIZE_CRED){
            s->username[s->read++] = b;
        }
    }
    else{
        if(s->read != 0){
            s->username[s->read] = '\0';
            s->read = 0;
            s->remaining = strlen(PASS);
            s->check_read = 0;
            s->check_remaining = strlen(ERR);
            st = POP3_PASS;
        } 
    }
    return st;
}

enum pop3sniff_state read_pass(struct pop3_sniffer* s,uint8_t b){
    enum pop3sniff_state st = POP3_READ_PASS;
    if(b != '\n'){
        // No leemos los espacios
        if(s->read < MAX_SIZE_CRED){
            s->password[s->read++] = b;
        }
    }
    else{
        if(s->read != 0){
            s->password[s->read] = '\0';
            s->read = 0;
            s->check_read = 0;
            st = POP3_CHECK;
        } 
    }
    return st;
}

enum pop3sniff_state check(struct pop3_sniffer* s,uint8_t b){
    enum pop3sniff_state st = POP3_CHECK;
    if(tolower(b) == tolower(*(OK + s->read))){
        s->read++;
        if(s->read == strlen(OK)){
            st = POP3_SUCCESS;
        }
    }
    else if(tolower(b) == tolower(*(ERR + s->check_read))){
        s->check_read++;
        if(s->check_read == strlen(ERR)){
            st = POP3_USER;
        }
    }
    return st;
}

enum pop3sniff_state pop3_sniffer_parse(struct pop3_sniffer* s,uint8_t b){
    switch (s->state)
    {
    case POP3_INITIAL:
        s->state = initial_msg(s,b);
        break;
    case POP3_USER:
        s->state = keyword(s,b,USER,POP3_USER,POP3_READ_USER);
        // s->state = user(s,b);
        break;
    case POP3_READ_USER:
        s->state = read_user(s,b);
        break;
    case POP3_PASS:
        s->state = keyword(s,b,PASS,POP3_PASS,POP3_READ_PASS);
        break;
    case POP3_READ_PASS:
        s->state = read_pass(s,b);
        break;
    case POP3_CHECK:
        s->state = check(s,b);
        break;    
    case POP3_SUCCESS:
        /* nada que hacer, parseo finalizado */
        break;  
    case POP3_DONE:
        /* nada que hacer, parseo finalizado */
        break;    
    default:
        break;
    }
    return s->state;
}

bool pop3_is_done(struct pop3_sniffer *s){
    return s->state == POP3_DONE || s->state == POP3_SUCCESS;
}

bool pop3_is_parsing(struct pop3_sniffer *s){
    return s->parsing;
}

enum pop3sniff_state pop3_consume(struct pop3_sniffer *s,struct log_info *log){
    uint8_t * ptr;
    ssize_t count;
    while(buffer_can_read(&s->buffer) && !pop3_is_done(s)){
        uint8_t b = buffer_read(&s->buffer);
        pop3_sniffer_parse(s,b);
    }
    if(s->state == POP3_SUCCESS){
        log->user = s->username;
        log->passwd = s->password;
        log->protocol = POP3;
        log_sniff(log);
    }
    return s->state;
}