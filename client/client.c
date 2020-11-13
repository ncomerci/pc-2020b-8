#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>  // socket
#include <arpa/inet.h>
#include <stdbool.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <errno.h>
#include <stdlib.h>
#include <string.h> /* memset */
#include <signal.h>
#include <unistd.h>
#include <math.h>

#define N(x) sizeof(x)/sizeof(x[0])
#define MAX_CRED_SIZE 256
#define CANT_MENU_OPTIONS 14

// ================================================================
// ==================== GLOBAL DEFINITIONS ========================
// ================================================================
static bool done = false;
static char input[6] = "%";

struct user
{
    char *name;
    char *pass;
};

struct mng_args
{

    char *mng_addr;
    unsigned short mng_port;

    struct user user;
};

static enum resp_status {success = 0x00, server_failure, cmd_unsupported, type_unsupported, arg_error, user_not_found, user_no_space, TOTAL_RESPONSES} status;
static char *resp_string[] = {"Success", "Server failure", "Command unsupported", "Type unsuppurted", "Argument error", "User not found", "Couldn't add user (lack of space)"};
typedef enum resp_status resp_status;

// ================================================================
// ================================================================

// =============== PROTOCOL GET FUNCTIONS ===============
static void get_transfered_bytes(int fd);
static void get_historical_connections(int fd);
static void get_concurrent_connections(int fd);
static void get_users_list(int fd);

// =============== PROTOCOL SET FUNCTIONS ===============
static void set_new_user(int fd);
static void set_remove_user(int fd);
static void set_change_pass(int fd);
static void set_sniffer_handler(int fd);
static void set_doh_ip(int fd);
static void set_doh_port(int fd);
static void set_doh_host(int fd);
static void set_doh_path(int fd);
static void set_doh_query(int fd);

// =============== PROTOCOL MISC FUNCTIONS ===============
static void quit(int fd);

// =============== PRIVATE FUNCTIONS ===============
static void version();
static void usage(const char *progname);
static void user(char *s, struct user *user);
static void sigterm_handler(const int signal);
static void sigpipe_handler();
static void input_init();
static void exit_error();
static unsigned short port(const char *s);
static int send_getter_request(int fd, uint8_t cmd);
static uint8_t **get_getter_result(int fd, resp_status *status, size_t *cant_args);
static void free_args(uint8_t **args, size_t cant_args);

inline static void clear_buffer() {
    char c;
    do{
        c = getchar();
    }while (c != '\n' && c != EOF);
}


// ==================================================================
void parse_args(const int argc, char **argv,struct mng_args * args);
void login(int fd, struct user *user);
void menu(int fd);

static void (*menu_functions[CANT_MENU_OPTIONS])(int fd) = { get_transfered_bytes, 
            get_historical_connections, get_concurrent_connections, get_users_list, 
            set_new_user, set_remove_user, set_change_pass, set_sniffer_handler,
            set_doh_ip, set_doh_port, set_doh_host, set_doh_path, set_doh_query, quit};


int main(const int argc, char **argv){

    struct mng_args args;
    parse_args(argc, argv, &args);

    int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP);

    struct sockaddr_in sv;
    sv.sin_port = htons(args.mng_port);
    sv.sin_family = AF_INET;
    inet_pton(AF_INET,args.mng_addr,&sv.sin_addr);

    if(-1 == connect(fd,(struct sockaddr *)&sv,sizeof(sv))){
        perror("couldn't connect");
        return -1;
    }

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);
    signal(SIGPIPE, sigpipe_handler);

    input_init();

    login(fd, &args.user);

    menu(fd);
    
    close(fd);
    status = success;
    return 0;
}

void parse_args(const int argc, char **argv,struct mng_args * args){
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users
    args->mng_addr = "127.0.0.1";
    args->mng_port = 8080;
    int c;
    while (true)
    {

        c = getopt(argc, argv, "hL:P:a:v");
        if (c == -1)
            break;

        switch (c)
        {
        case 'h':
            usage(argv[0]);
            exit(1);
            break;
        case 'L':
            args->mng_addr = optarg;
            break;
        case 'P':
            args->mng_port = port(optarg);
            break;
        case 'a':
            user(optarg, &args->user);
            break;
        case 'v':
            version();
            exit(0);
            break;
        default:
            usage(argv[0]);
            exit(1);
        }
    }
    if (optind < argc)
    {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc)
        {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}

void login(int fd, struct user *user_info) {

    enum login_responses {
        LOGIN_SUCCESFUL = 0x00,
        UNSUPPORTED_VERSION = 0x01,
        INCORRECT_USER_PASS = 0x02,
        SERVER_FAILURE = 0x03,
    };
    
    uint8_t * first_msg = NULL;
    bool login_completed = false;

    char user[MAX_CRED_SIZE], pass[MAX_CRED_SIZE];

    while(!done && !login_completed) {
        // Si no recibo user/pass pedirlos.
        if(user_info->name == 0 && user_info->pass == 0){
            printf("Enter username: ");
            scanf(input, user);
            printf("Enter password: ");
            scanf(input, pass);
        }
        else {
            strcpy(user, user_info->name);
            strcpy(pass, user_info->pass);
        }

        size_t user_len = strlen(user);
        size_t pass_len = strlen(pass);
        // Create first message
        first_msg = realloc(first_msg, 3 + strlen(user) + strlen(pass) + 1);
        first_msg[0] = 0x01;
        first_msg[1] = user_len;
        strcpy((char *)(first_msg + 2) , user);
        first_msg[2 + user_len] = pass_len;
        strcpy((char *)(first_msg + 3 + user_len), pass);

        send(fd, first_msg, strlen((char *)first_msg), MSG_NOSIGNAL);
        uint8_t res[2];
        recv(fd, res, 2, 0);

        switch(res[1]) {
            case UNSUPPORTED_VERSION: {
                fprintf(stderr, "Protocol version not supported\n");
                done = true;
                break;
            }
            case LOGIN_SUCCESFUL: {
                printf("Login succesful!\n");
                login_completed = true;
                break;
            }
            case INCORRECT_USER_PASS: {
                fprintf(stderr, "User or password is not correct\n");
                done = true;
                break;
            }
            case SERVER_FAILURE: {
                fprintf(stderr, "Server failure\n");
                done = true;
                break;
            }
            default: {
                fprintf(stderr, "Unknown response\n");
                done = true;
            }
        }

    }
    if(first_msg != NULL) free(first_msg);
}

static void exit_error() {
    printf("An error has ocurred\n");
    done = true;
}

static void print_menu_options() {
    system("clear"); //clear screen
    printf("01. (GET) transefered bytes\n02. (GET) historical connections\n03. (GET) concurrent connections\n04. (GET) users list\n\n05. (SET) add new users\n06. (SET) remove user\n07. (SET) change password to an user\n08. (SET) enable/disable password sniffer\n09. (SET) DOH IP\n10. (SET) DOH port\n11. (SET) DOH host\n12. (SET) DOH path\n13. (SET) DOH query\n14. QUIT\n\n");
    
}

static void leave_print() {
    printf("\nPress [ENTER] to return\n");
    char opt = 0;
    do {
        scanf("%c", &opt);
        clear_buffer();
    }while(opt != '\n' && opt != EOF);
}

static void print_get_results(char *results[], size_t cant_results) {
    if(cant_results == 0) {
        printf("No results...\n\n");
    }
    else {
        for(size_t i = 0 ; i < cant_results ; i++) {
            printf("%s\n", results[i]);
        }
        putc('\n', stdout);
    }
    
    leave_print();
}

static void print_response_status(resp_status status) {

    if(status >= 0 && status < TOTAL_RESPONSES) {
        printf("Server response was: %s\n", resp_string[status]);
    }
    else {
        printf("Unknown received status\n");
    }
    leave_print();
} 

void menu(int fd) {

    char selected_opt[MAX_CRED_SIZE];
    int select;
    while (!done)
    {
    print_menu_options();

    printf("Choose an option: ");
    scanf(input, selected_opt);

    select = atoi(selected_opt) - 1;

    if(select >= 0 && select < CANT_MENU_OPTIONS && !done) {
        menu_functions[select](fd);
    }
    }
}

static void input_init() {
    snprintf(input+1, sizeof(input)-2, "%d", MAX_CRED_SIZE-1);
    int len = strlen(input);
    input[len] = 's';
    input[len+1] = '\0';
}

static int send_getter_request(int fd, uint8_t cmd) {
    uint8_t request[2];

    request[0] = 0x00;
    request[1] = cmd;

    int n = send(fd, request, 2, 0);

    if(n <= 0) {
        exit_error();
    }

    return n;
}

static uint8_t **get_getter_result(int fd, resp_status *status, size_t *cant_args) {
    const int min_size = 4;
    uint8_t min_buffer[min_size];
    int n;

    n = recv(fd, min_buffer, min_size, 0);

    if(n < min_size - 1) {
        *status = server_failure;
        return NULL;
    }

    *status = min_buffer[0];

    if(*status != success) {
        return NULL;
    }

    *cant_args = min_buffer[2];

    uint8_t **args = malloc(*cant_args * sizeof(char *));

    if(args == NULL) {
        return NULL;
    }

    size_t arg_len = min_buffer[3];

    for(size_t i = 0 ; i < *cant_args ; i++) {

        args[i] = malloc(arg_len * sizeof(uint8_t) + 2);

        if(args[i] == NULL) {
            *cant_args = i - 1;
            return args;
        }

        recv(fd, args[i], arg_len + 1, 0);
        
        if(i + 1 < *cant_args) n = args[i][arg_len];

        args[i][arg_len] = '\0';

        arg_len = n;
    }

    return args;
}

static void free_args(uint8_t **args, size_t cant_args) {
    for(size_t i = 0 ; i < cant_args ; i++) {
        free(args[i]);
    }

    free(args);
}

static int send_setter_request(int fd, uint8_t cmd, uint8_t **args, uint8_t cant_args, size_t *args_len) {

    uint8_t *setter = malloc(3 * sizeof(uint8_t));
    uint8_t *aux;
    int setter_len = 3;
    int ret = 0;
    int aux_len;

    if(setter == NULL) {
        return -1;
    }

    setter[0] = 0x01;
    setter[1] = cmd;
    setter[2] = cant_args;

    for(size_t i = 0; i < cant_args ; i++) {

        if(args_len[i] > 255) {
            ret = -1;
            goto final;
        }

        aux_len = setter_len + args_len[i] + 1;
        aux = realloc(setter, aux_len);

        if(aux == NULL) {
            ret = -1;
            goto final;
        }

        setter = aux;

        setter[setter_len] = args_len[i];
        memcpy(setter + setter_len + 1, args[i], args_len[i]);
        setter_len = aux_len;
    }

    ret = send(fd, setter, setter_len, 0);

final:
    free(setter);
    return ret;
}

static int get_setter_result(int fd, resp_status *status) {
    char buff[1];
    int n = recv(fd, buff, 1, 0);
    *status = buff[0];
    return n;
}

static uint8_t **send_and_receive_getter_request(int fd, int cmd, size_t *cant_args) {
    if(send_getter_request(fd, cmd) <= 0) {
        return NULL;
    }

    resp_status status;
    uint8_t **response = get_getter_result(fd, &status, cant_args);

    if(response == NULL) {
        if(status != success) {
            print_response_status(status);
        }
        else {
            perror(strerror(errno));
        }
    }

    return response;
}

static void get_transfered_bytes(int fd) {

    size_t cant_args;
    uint8_t **response = send_and_receive_getter_request(fd, 0x00, &cant_args);

    if(response == NULL) {
        return;
    }

    if(cant_args != 1) {
        goto final;
    }

    unsigned long bytes = (response[0][0] << 24) | (response[0][1] << 16) | (response[0][2] << 8) | response[0][3];

    size_t bytes_num_len;
    if(bytes == 0) {
        bytes_num_len = 1;
    } 
    else {
        bytes_num_len = floor(log10(bytes)) + 1;
    }

    char *msg = "total transfered = %u B";
    char *result[1];
    size_t msg_len = strlen(msg) + bytes_num_len;
    result[0] = malloc(msg_len + 1);

    if(result[0] == NULL) {
        goto final;
    }

    snprintf(result[0], msg_len, msg, bytes);

    print_get_results(result, cant_args);

    free(result[0]);

final:
    free_args(response, cant_args);
}

static void get_connections(int fd, int cmd, char *msg_format) {

    size_t cant_args;
    uint8_t **response = send_and_receive_getter_request(fd, cmd, &cant_args);

    if(response == NULL) {
        return;
    }

    if(cant_args != 1) {
        goto final;
    }

    unsigned long num = (response[0][0] << 8) | response[0][1];

    size_t num_len;
    if(num == 0) {
        num_len = 1;
    } 
    else {
        num_len = floor(log10(num)) + 1;
    }

    char *result[1];
    size_t msg_len = strlen(msg_format) - 3 + num_len;
    result[0] = malloc(msg_len + 1);

    if(result[0] == NULL) {
        goto final;
    }

    snprintf(result[0], msg_len, msg_format, num);

    print_get_results(result, cant_args);

    free(result[0]);

final:
    free_args(response, cant_args);
}

static void get_historical_connections(int fd) {
    get_connections(fd, 0x01, "Historical connections = %ul\n");
}

static void get_concurrent_connections(int fd) {
    get_connections(fd, 0x02, "Concurrent connections = %ul\n");
}

static void get_users_list(int fd) {
    size_t cant_args;
    uint8_t **response = send_and_receive_getter_request(fd, 3, &cant_args);

    if(response == NULL) {
        return;
    }

    printf("\nUSUARIOS:\n\n");
    print_get_results((char **) response, cant_args);

    free_args(response, cant_args);
}

static void send_and_receive_setter_request(int fd, int cmd, uint8_t **args, uint8_t cant_args, size_t *args_len) {
    int val = send_setter_request(fd, cmd, args, cant_args, args_len);

    if(val <= 0) {
        perror(strerror(errno));
        done = true;
    }

    resp_status status;
    val = get_setter_result(fd, &status);

    if(val <= 0) {
        if(val < 0) perror(strerror(errno));
        
        printf("Connection closed by server\n");
        done = true;
    }
    else {
        print_response_status(status);
    }
}

static void perform_user_action(int fd, int cmd, char *title) {
    char user[MAX_CRED_SIZE], pass[MAX_CRED_SIZE];

    printf("%s", title);
    printf("Username: ");
    scanf(input, user);
    putc('\n', stdout);
    printf("Password: ");
    scanf(input, pass);
    putc('\n', stdout);

    char confirm = 0;
    printf("\n\nAre you sure you want to perform this action? [Y]es or [N]o\n");
    do
    {
        clear_buffer();
        confirm = getchar();
    } while (confirm != 'y' && confirm != 'Y' && confirm != 'n' && confirm != 'N');

    if(confirm == 'n' || confirm == 'N') {
        return;
    }

    uint8_t cant_args = 2;

    uint8_t *args[3];
    uint8_t user_role[] = {0x01};

    args[0] = user_role;
    args[1] = (uint8_t *) user;
    args[2] = (uint8_t *) pass;

    size_t args_len[] = {1, strlen(user), strlen(pass)};

    if(cmd == 0x00) {
        printf("\n\nThis new user is Administrator? [Y]es or [N]o\n");
        do
        {
            clear_buffer();
            confirm = getchar();
        } while (confirm != 'y' && confirm != 'Y' && confirm != 'n' && confirm != 'N');

        if(confirm == 'y' || confirm == 'Y') {
            user_role[0] = 0x00;
        }

        cant_args = 3;
    }

    if(cant_args == 2) {
        send_and_receive_setter_request(fd, cmd, args + 1 , 2, args_len + 1);
    }
    else {
        send_and_receive_setter_request(fd, cmd, args, 3, args_len);
    }
}

static void set_new_user(int fd) {
    perform_user_action(fd, 0x00, "Adding new user\n\n");
}

static void set_remove_user(int fd) {
    char user[MAX_CRED_SIZE];

    printf("Removing an user\n\n");
    printf("Username: ");
    scanf(input, user);
    putc('\n', stdout);

    char confirm = 0;
    printf("\nAre you sure you want to remove this user? [Y]es or [N]o\n");
    do
    {
        clear_buffer();
        confirm = getchar();
    } while (confirm != 'y' && confirm != 'Y' && confirm != 'n' && confirm != 'N');

    if(confirm == 'n' || confirm == 'N') {
        return;
    }

    uint8_t *args[1];
    size_t arg_len[1];

    args[0] = (uint8_t *) user;
    arg_len[0] = strlen(user);

    send_and_receive_setter_request(fd, 0x01, args, 1, arg_len);
}

static void set_change_pass(int fd) {
    perform_user_action(fd, 0x02, "Change password\n\n");
}

static void set_sniffer_handler(int fd) {

    char confirm = 0;
    printf("\nPassword sniffer: press [E] to enable it or [D] to disable it\n");
    do
    {
        clear_buffer();
        confirm = getchar();
    } while (confirm != 'e' && confirm != 'E' && confirm != 'd' && confirm != 'D');

    uint8_t opt[] = {0x01, 0x03, 0x01, 0x01, 0x00};

    if(confirm == 'd' || confirm == 'D') {
        opt[4] = 0x01;
    }


    int n = send(fd, opt, 5, 0);

    if(n <= 0) {
        exit_error();
        return;
    }

    resp_status status;
    n = get_setter_result(fd, &status);

    if(n <= 0) {
        exit_error();
        return;
    }

    print_response_status(status);

}

static void doh_functions(int fd, int cmd, const char *title, bool (*validator)(char *, uint8_t *, uint8_t *)) {
    char user_input[MAX_CRED_SIZE];
    char confirm = 0;

        printf("%s", title);
        scanf(input, user_input);
    do{
        printf("\nAre you sure you want to perform this action? [Y]es or [N]o\n");
        clear_buffer();
        confirm = getchar();
    }
    while(confirm != 'y' && confirm != 'Y' && confirm != 'n' && confirm != 'N');

    if(confirm == 'n' || confirm == 'N') {
        return;
    }

    uint8_t *args[1];
    size_t arg_len[1];

    if(validator != NULL) {

        uint8_t size = 0;

        if(!validator(user_input, (uint8_t *) user_input, &size)) {
            printf("Invalid input\n");
            leave_print();
            return;
        }

        arg_len[0] = size;
    }
    else {
        arg_len[0] = strlen(user_input); 
    }

    args[0] = (uint8_t *) user_input;
    send_and_receive_setter_request(fd, cmd, args, 1, arg_len);
}

static bool doh_ip_validator(char * ip, uint8_t * result, uint8_t * size) {
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    bool ret = false;

    if(inet_pton(AF_INET, ip, &(sa.sin_addr))) {
        *size = 4;
        memcpy(result, &sa.sin_addr.s_addr, *size);
        ret = true;
    }
    else if(inet_pton(AF_INET6, ip, &(sa6.sin6_addr))) {
        *size = 16;
        memcpy(result, &sa6.sin6_addr.__in6_u.__u6_addr8, *size);
        ret = true;
    }

    return ret;
} 

static void set_doh_ip(int fd) {
    char user_input[MAX_CRED_SIZE];
    char confirm = 0;

        printf("\nInsert new IP address: ");
        scanf(input, user_input);
    do{
        printf("\nAre you sure you want to perform this action? [Y]es or [N]o\n");
        clear_buffer();
        confirm = getchar();
    }
    while(confirm != 'y' && confirm != 'Y' && confirm != 'n' && confirm != 'N');

    if(confirm == 'n' || confirm == 'N') {
        return;
    }

    uint8_t *args[2];
    size_t arg_len[2];
    uint8_t ip_type[1];

    uint8_t size = 0;

    if(!doh_ip_validator(user_input, (uint8_t *) user_input, &size)) {
        printf("Invalid input\n");
        leave_print();
        return;
    }

    if(size == 4) {
        ip_type[0] = 0x00;
    }
    else if(size == 16) {
        ip_type[0] = 0x01;
    }
    else {
        exit_error();
        return;
    }

    arg_len[0] = 1;
    arg_len[1] = size;

    args[0] = ip_type;
    args[1] = (uint8_t *) user_input;
    send_and_receive_setter_request(fd, 0x04, args, 2, arg_len);

}

static bool doh_port_validator(char *port, uint8_t * result, uint8_t * size) {
    int len = strlen(port);
    if(len > 5) return false; // 5 es la máxima cantidad de dígitos que puede tener un puerto

    uint16_t num_port = 0;

    for(int i = 0; i < len ; i++) {
        if(port[i] >= '0' && port[i] <= '9') {
            num_port = num_port * 10 + (port[i] - '0');
        }
        else return false;
    }

    *size = 2;
    result[0] = num_port >> 8;
    result[1] = num_port;

    return true;
}

static void set_doh_port(int fd) {
    doh_functions(fd, 0x05, "Insert new Port: ", doh_port_validator);
}

static void set_doh_host(int fd) {
    doh_functions(fd, 0x06, "Insert new Host: ", NULL);
}

static void set_doh_path(int fd) {
    doh_functions(fd, 0x07, "Insert new Path: ", NULL);
}

static void set_doh_query(int fd) {
    doh_functions(fd, 0x08, "Insert new Query: ", NULL);
}

static unsigned short port(const char *s) {
    char *end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 || sl > USHRT_MAX)
    {
        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
        exit(1);
        return 1;
    }
    return (unsigned short)sl;
}

static void user(char *s, struct user *user) {
    char *p = strchr(s, ':');
    if (p == NULL || strlen(p) == 1)
    {
        fprintf(stderr, "password not found.\n");
        exit(1);
    }
    else
    {
        *p = 0;
        if(strlen(s) == 0){
            fprintf(stderr, "username not found.\n");
            exit(1);
        }
        p++;
        user->name = s;
        user->pass = p;
    }
}

static void sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

static void sigpipe_handler() {
    printf("Server closed connection, cleaning up and exiting\n");
    done = true;
}

static void usage(const char *progname){
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -L <conf addr>  Dirección donde servirá el servicio de management. Por defecto utiliza loopback.\n"
            "   -P <conf port>   Puerto entrante conexiones configuracion. Por defecto el valor es 8080\n"
            "   -u <name>:<pass> Usuario y contraseña de usuario para identificarse ante el servidor. Por defecto se pregunta.\n"
            "   -v               Imprime información sobre la versión y termina.\n"
            "\n",
            progname);
}

static void version(){
    fprintf(stderr, "Cliente protocolo G8 version 1.0\n"
                    "ITBA Protocolos de Comunicación 2020/2 -- Grupo 8\n"
                    "AQUI VA LA LICENCIA\n");
}


static void quit(int fd) {
    uint8_t buff[] = {0x02};
    send(fd, buff, 1, 0);

    int n = recv(fd, buff, 1, 0);

    if(n != 1) {
        exit_error();
    }
    else {
        print_response_status(buff[0]);
    }

    done = true;
}