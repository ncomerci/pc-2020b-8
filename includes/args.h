#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#include <stdint.h>
#include <stdbool.h>
/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */

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
