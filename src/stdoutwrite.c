#include "../includes/stdoutwrite.h"
#define N(x) (sizeof(x)/sizeof((x)[0]))

struct write *write_data = NULL;

struct write * get_write_data(){
    return write_data;
}

int init_write(fd_selector selector){
    write_data = malloc(sizeof(*write_data));
    if(write_data == NULL){
        return -1;
    }
    write_data->selector = selector;
    buffer_init(&write_data->wb, N(write_data->raw_buff), write_data->raw_buff);
    return 1;
}

void free_write(){
    if(write_data != NULL){
        free(write_data);
    }
}


void write_handler(struct selector_key * key){
    struct write *w = (struct write *)key->data;
    
    size_t size;
    buffer *b = &w->wb;
    uint8_t *ptr = buffer_read_ptr(b, &size);
    // n = send(key->fd,)
    ssize_t n = write(1, ptr,size);
    if(n > 0){
        if((unsigned)n < size){
            buffer_read_adv(b,n);
        }
        else{
            buffer_read_adv(b,size);
            selector_set_interest_key(key, OP_NOOP);
        }
    }
}