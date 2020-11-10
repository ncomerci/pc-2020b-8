#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <limits.h> /* LONG_MIN et al */
#include <string.h> /* memset */
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#define MAX_USERS 10

struct users
{
    char *name;
    char *pass;
};

struct doh
{
    char *host;
    char *ip;
    unsigned short port;
    char *path;
    char *query;
};

struct socks5args
{
    char *socks_addr;
    unsigned short socks_port;

    char *mng_addr;
    unsigned short mng_port;

    bool disectors_enabled;

    struct doh doh;
    struct users users[MAX_USERS];
    int nusers;
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecuciÃ³n.
 */
void parse_args(const int argc, char **argv, struct socks5args *args);

void parse_args2(const int argc, char **argv);


void free_args();

// struct socks5args* get_args();

// getters and setters for args struct
char * get_args_socks_addr();

unsigned short get_args_socks_port();

struct users* get_args_users();

bool get_args_disectors_enabled();

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

int get_args_nusers();

void set_args_nusers(int new_val);

int add_new_user(char * user, char * pass);

int rm_user(char * user);
#endif
