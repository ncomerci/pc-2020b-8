#include "../includes/logger.h"



struct logger {
    size_t historical_conections;   // una por usuario
    size_t concurrent_conections;   // una por usuario
    size_t total_bytes_transfered;  // aumenta cada vez que se hace un send con la cantidad enviada
};


// config en runtime -> cambiar tamaño de buffers