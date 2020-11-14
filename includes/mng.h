#ifndef MNG_H
#define MNG_H
#include "selector.h"

/**
 * Se encarga del manejo del protocolo de configuración
 * contiene las estructuras que permiten el manejo de los
 * estados de la conexión con el cliente
**/ 
void mng_passive_accept(struct selector_key * key);


#endif