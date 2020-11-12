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
#define CANT_MENU_OPTIONS 13

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

static enum resp_status {success = 0x00, server_failure, cmd_unsupported, type_unsupported, arg_error, user_not_found, user_no_space};
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
static void set_doh_query(int fd);

// =============== PROTOCOL MISC FUNCTIONS ===============
static void quit(int fd);

// =============== PRIVATE FUNCTIONS ===============
static void version();
static void usage(const char *progname);
static void user(char *s, struct user *user);
static void sigterm_handler(const int signal);
static void input_init();
static unsigned short port(const char *s);
static int send_getter_request(int fd, uint8_t cmd);
static uint8_t **get_getter_result(int fd, resp_status *status, size_t *cant_args);
static void free_args(uint8_t **args, size_t cant_args);


// ==================================================================
void parse_args(const int argc, char **argv,struct mng_args * args);
void login(int fd, struct user *user);
void menu(int fd);

static void (*menu_functions[CANT_MENU_OPTIONS])(int fd) = {get_transfered_bytes, set_new_user};


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

    input_init();

    login(fd, &args.user);

    menu(fd);
    
    close(fd);
    return 0;
}

void parse_args(const int argc, char **argv,struct mng_args * args){
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users
    args->mng_addr = "127.0.0.1";
    args->mng_port = 8080;
    int c;
    while (true)
    {

        c = getopt(argc, argv, "hL:P:u:v");
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
        case 'u':
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
        UNSUPPORTED_VERSION = 0x00,
        LOGIN_SUCCESFUL = 0x01,
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
                fprintf(stderr, "User or password is not correct, please try again\n");
                user_info->name = '\0';
                user_info->pass = '\0';
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

static void print_menu_options() {
    system("clear"); //clear screen
    printf("01. (GET) transefered bytes\n02. (GET) historical connections\n03. (GET) concurrent connections\n04. (GET) users list\n\n05. (SET) add new users\n06. (SET) remove user\n07. (SET) change password to an user\n08. (SET) enable/disable password sniffer\n09. (SET) DOH IP\n10. (SET) DOH port\n11. (SET) DOH host\n12. (SET) DOH path\n13. (SET) DOH query\n\n");
    
}

static void leave_print() {
    printf("\nPress [ENTER] to return\n");
    char opt = 0;
    do {
        scanf("%1s", &opt);
    }while(opt != '\n');
}

static void print_get_results(char * results[], size_t cant_results) {
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

    printf("Server response was: %s\n", resp_string[status]);
    leave_print();
} 

void menu(int fd) {

    char selected_opt[MAX_CRED_SIZE];
    while (!done)
    {
        print_menu_options();

        printf("Choose an option: ");
        scanf(input, selected_opt);
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

    return send(fd, request, 2, 0);
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

        arg_len = args[i][arg_len + 1];
        args[i][arg_len + 1] = '\0';
    }

    return args;
}

static void free_args(uint8_t **args, size_t cant_args) {
    for(size_t i = 0 ; i < cant_args ; i++) {
        free(args[i]);
    }

    free(args);
}

static int send_setter_request(int fd, uint8_t cmd, uint8_t **args, uint8_t cant_args) {

    uint8_t *setter = malloc(3 * sizeof(uint8_t));
    int setter_len;
    int ret = 0;

    if(setter == NULL) {
        return -1;
    }

    setter[0] = 0x01;
    setter[1] = cmd;
    setter[2] = cant_args;

    for(size_t i = 0; i < cant_args ; i++) {
        const size_t arg_len = sizeof(args[i]);

        if(arg_len > 255) {
            ret = -1;
            goto final;
        }

        setter_len = sizeof(setter)/sizeof(uint8_t);
        setter = realloc(setter, setter_len + arg_len + 1);

        if(setter == NULL) {
            return -1;
        }

        setter[setter_len] = (uint8_t) arg_len;
        memcpy(setter + setter_len + 1, args[i], arg_len);
    }

    setter_len = sizeof(setter)/sizeof(uint8_t);
    ret = send(fd, setter, setter_len, 0);

final:
    free(setter);
    return ret;
}

static int get_setter_result(int fd, resp_status *status) {
    return recv(fd, status, 1, 0);
}

static void get_transfered_bytes(int fd) {

    send_getter_request(fd, 0x00);

    resp_status status;
    size_t cant_args;
    uint8_t **response = get_getter_result(fd, &status, &cant_args);

    if(response == NULL) {
        if(status != success) {
            print_response_status(status);
        }
        else {
            perror(strerror(errno));
        }
        return;
    }

    if(cant_args > 1) {
        goto final;
    }

    unsigned long bytes = (response[0][3] << 24) | (response[0][2] << 16) | (response[0][1] <<8) | response[0][0];

    size_t bytes_num_len;
    if(bytes == 0) {
        bytes_num_len = 1;
    } 
    else {
        bytes_num_len = floor(log10(bytes)) + 1;
    }

    char *msg = "total transfered = %ul B";
    char *result[1];
    size_t msg_len = sizeof(msg) - 3 + bytes_num_len;
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

static void set_new_user(int fd) {
    char user[MAX_CRED_SIZE], pass[MAX_CRED_SIZE];

    printf("Adding new user\n\n");
    printf("Username: ");
    scanf(input, user);
    putc('\n', stdout);
    printf("Password: ");
    scanf(input, pass);
    putc('\n', stdout);

    char confirm = 0;
    printf("\n\n Are you sure you want to add this user? [Y]es or [N]o\n");
    do
    {
        scanf("%1s", &confirm);
    } while (confirm != 'y' || confirm != 'Y' || confirm != 'n' || confirm != 'N');

    if(confirm == 'n' || confirm == 'N') {
        return;
    }

    uint8_t *args[2];

    args[0] = (uint8_t *) user;
    args[1] = (uint8_t *) pass;

    int val = send_setter_request(fd, 0x00, args, 2);

    if(val <= 0) {
        perror(strerror(errno));
    }
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
