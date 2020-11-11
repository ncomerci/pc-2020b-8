#ifndef MNG_H
#define MNG_H
#include "selector.h"
#include <sys/socket.h>
#include "stm.h"
#include "buffer.h"
#include <stdint.h>
#include "auth.h"
#include "cmd.h"
#include "args.h"

void mng_passive_accept(struct selector_key * key);


#endif