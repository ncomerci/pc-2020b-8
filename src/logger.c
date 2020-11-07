#include "../includes/logger.h"
#include <string.h>
struct logger {
    size_t historical_conections;   // una por usuario
    size_t concurrent_conections;   // una por usuario
    size_t total_bytes_transfered;  // aumenta cada vez que se hace un send con la cantidad enviada
};

static void date_to_string(char * date){
    
    time_t timer = time(NULL);
    struct tm * tm = gmtime(&timer);
    strftime(date,DATE_SIZE,"%Y-%m-%dT%TZ",tm);
    // fprintf(stdout,"[%s]\n",date);
    // return date;
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

static char* dest_addr_to_string(struct log_info socks_info){
    char *ip; 
    switch (socks_info.atyp)
    {
    case ipv4_type:
        ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET,&socks_info.dest_addr.ipv4.sin_addr, ip, INET_ADDRSTRLEN);
        break;
    case ipv6_type:
        ip = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET6,&socks_info.dest_addr.ipv6.sin6_addr, ip, INET6_ADDRSTRLEN);
        break;
    case domainname_type:
        ip = (char *)malloc((strlen(socks_info.dest_addr.fqdn)+1) * sizeof(char));
        strcpy(ip,socks_info.dest_addr.fqdn);
        break;
    }
    return ip;
}

void log_access(struct log_info socks_info){
    char date[DATE_SIZE];
    date_to_string(date);
    int length = socks_info.client_addr.ss_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;;
    char ret[length];
    ip_to_string(socks_info.client_addr, ret,length);
    char * dest_ip = dest_addr_to_string(socks_info);
    fprintf(stdout,"[%s]    %s    A    %s    %u    %s    %u    status=%d\n", date, user_to_string(&socks_info), ret, ntohs(addr_port(socks_info.client_addr)), dest_ip, ntohs(socks_info.dest_port),socks_info.status);
    free(dest_ip);
}
// config en runtime -> cambiar tamaño de buffers