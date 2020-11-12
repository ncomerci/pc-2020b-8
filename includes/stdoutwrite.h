#ifndef STDOUTWRITE_H
#define STDOUTWRITE_H
#include "selector.h"
#include "buffer.h"
#define MAX_WRITE_BUFF 2048

struct write{
    uint8_t raw_buff[MAX_WRITE_BUFF];
    buffer wb;
    fd_selector selector;
};

void write_handler(struct selector_key * key);
int init_write(fd_selector selector);
void free_write();
struct write * get_write_data();
#endif

