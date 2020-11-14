#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdint.h>
#include "khash.h"

#define MAX_USERS 10
#define MAX_CRED_SIZE 255
#define MAX_IP_SIZE 16

KHASH_MAP_INIT_STR(admins, char*)
KHASH_MAP_INIT_STR(users, char*)
/**
**  Estructura donde se guardan los argumentos de la linea de comando
**  y las variables que monitorean el uso del servidor y opciones de
**  configuración del protocolo de configuración.
**/
struct users
{
    char name[MAX_CRED_SIZE];
    char pass[MAX_CRED_SIZE];
};

struct doh
{
    char host[MAX_CRED_SIZE+2];
    char ip[MAX_IP_SIZE];
    unsigned short port;
    char path[MAX_CRED_SIZE];
    char query[MAX_CRED_SIZE];
};

struct socks5info
{
    char *socks_addr4;
    char *socks_addr6;
    unsigned short socks_port;

    char *mng_addr4;
    char *mng_addr6;
    unsigned short mng_port;

    // Define si se habilita sniffing
    bool disectors_enabled;

    // Almacena las variables de DoH
    struct doh doh;

    // Almacena los users
    khash_t(users) *hu;

    // Almacena la cantidad de usuarios
    int nusers;

    // Almacena los admins
    khash_t(admins) *ha;

    // Almacena la cantidad de admins
    int nadmins;

    // Almacena todas las conexiones historicas de clientes
    uint16_t historical_conections;   

    // Almacena todas las conexiones de clientes concurrentes
    uint16_t concurrent_conections;   

    // Almacena todos los bytes transferidos, de cliente a origen y viceversa
    uint32_t total_bytes_transfered;  
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
// void parse_args(const int argc, char **argv, struct socks5args *args);

void parse_args(const int argc, char **argv);


void free_args();


// getters and setters for info struct

// ************ SOCKS ************ 

char * get_args_socks_addr4();

char * get_args_socks_addr6();

unsigned short get_args_socks_port();

bool get_args_disectors_enabled();

void set_args_disectors_enabled(bool value);

// ************ MNG ************ 

char * get_args_mng_addr4();

char * get_args_mng_addr6();

unsigned short get_args_mng_port();

// ************ DOH ************ 
char * get_args_doh_ip();
void set_args_doh_ip(char * new_ip);

char * get_args_doh_host();
void set_args_doh_host(char * new_host);

unsigned short get_args_doh_port();
void set_args_doh_port(unsigned short new_port);

char * get_args_doh_path();
void set_args_doh_path(char * new_path);

char *get_args_doh_query();
void set_args_doh_query(char * new_query);


// ************ USERS/ADMINS ************ 

int get_args_nusers();

void set_args_nusers(int new_val);

int get_args_nadmins();

void set_args_nadmins(int new_val);

int add_new_admin(char * user, char * pass);

int add_new_user(char * user, char * pass);

int delete_registered(char * user);

int change_user_pass(char *user, char *pass);

int check_admin_credentials(char * user, char * pass);

int registed(char * user, char * pass);

char * get_all_users();

// ************ MONITORING ************ 

uint16_t get_historical_conections();
void set_historical_conections(uint16_t amount);

uint16_t get_concurrent_conections();
void set_concurrent_conections(uint16_t amount);

uint32_t get_total_bytes_transfered();
void set_total_bytes_transfered(uint32_t amount);

#endif
