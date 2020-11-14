#include <string.h>
#include <stdio.h>
#include "../includes/logger.h"
#include "../includes/socks5nio.h"
#include "../includes/hello.h"
#include "../includes/stdoutwrite.h"

static void date_to_string(char * date){
    
    time_t timer = time(NULL);
    struct tm * tm = gmtime(&timer);
    strftime(date,DATE_SIZE,"%Y-%m-%dT%TZ",tm);
}


static const char * ip_to_string(struct sockaddr_storage addr,char *ret,int length){
    if(addr.ss_family == AF_INET){
        return inet_ntop(addr.ss_family, &(((struct sockaddr_in *)&addr)->sin_addr), ret, length);

    }
    else{
        return inet_ntop(addr.ss_family, &(((struct sockaddr_in6 *)&addr)->sin6_addr), ret, length);
    }
}

static char* user_to_string(struct log_info* socks_info){
    if(socks_info->method == METHOD_NO_AUTHENTICATION_REQUIRED){
        return "----";
    }
    else{
        return (char*) socks_info->user_info.uname;
    }
}

static in_port_t addr_port(struct sockaddr_storage addr){
    return addr.ss_family == AF_INET ? ((struct sockaddr_in*)&addr)->sin_port : ((struct sockaddr_in6*)&addr)->sin6_port;
}

static char* dest_addr_to_string(struct log_info *socks_info){
    char *ip; 
    switch (socks_info->atyp)
    {
    case ipv4_type:
        ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET,&socks_info->dest_addr.ipv4.sin_addr, ip, INET_ADDRSTRLEN);
        break;
    case ipv6_type:
        ip = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET6,&socks_info->dest_addr.ipv6.sin6_addr, ip, INET6_ADDRSTRLEN);
        break;
    case domainname_type:
        ip = (char *)malloc((strlen(socks_info->dest_addr.fqdn)+1) * sizeof(char));
        strcpy(ip,socks_info->dest_addr.fqdn);
        break;
    }
    return ip;
}

static void print_log(struct log_info *socks_info, char type) {
    char date[DATE_SIZE];
    date_to_string(date);
    int length = socks_info->client_addr.ss_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    char ret[length];
    ip_to_string(socks_info->client_addr, ret,length);
    char * dest_ip = dest_addr_to_string(socks_info);
    char *print = NULL;
    size_t count;
    struct write* write_data = get_write_data();
    uint8_t * ptr = buffer_write_ptr(&write_data->wb,&count);
    int n = 0;
    if(type == 'A') {
        print = "[%s]\t%s\tA\t%s\t%u\t%s\t%u\tstatus=%d\n";
        // fprintf(stdout, print, date, user_to_string(socks_info), ret, ntohs(addr_port(socks_info->client_addr)), dest_ip, ntohs(socks_info->dest_port),socks_info->status);
        n = snprintf((char*)ptr,count,print, date, user_to_string(socks_info), ret, ntohs(addr_port(socks_info->client_addr)), dest_ip, ntohs(socks_info->dest_port),socks_info->status);
    }
    else if(type == 'P') {
        print = "[%s]\t%s\tP\t%s\t%s\t%u\t%s\t%s\n";
        // fprintf(stdout, print, date, user_to_string(socks_info), protocol_str[socks_info->protocol], dest_ip, ntohs(socks_info->dest_port), socks_info->user, socks_info->passwd);
        n = snprintf((char*)ptr,count,print, date, user_to_string(socks_info), protocol_str[socks_info->protocol], dest_ip, ntohs(socks_info->dest_port), socks_info->user, socks_info->passwd);
    }
    if(n < 0){
        // Error en la copia
    }
    if ((unsigned)n > count){
        buffer_write_adv(&write_data->wb,count);
    }
    else{
        buffer_write_adv(&write_data->wb,n);
    }
    selector_set_interest(write_data->selector,1, OP_WRITE);
    free(dest_ip);
}

void log_access(struct log_info *socks_info){
    print_log(socks_info, 'A');
}
// config en runtime -> cambiar tamaño de buffers

void log_sniff(struct log_info *socks_info) {
    print_log(socks_info, 'P');
}