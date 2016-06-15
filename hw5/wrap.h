#ifndef WRAP_H
#define WRAP_H
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <pthread.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#define _GNU_SOURCE

/* Define constants needed by both the client and server */
#define BUFFER_SIZE 256
#define MESSAGE_SIZE 1024
#define LISTEN_BACKLOG 128
#define HI_PRO "HI"
#define IAM_PRO "IAM"
#define WOLFIE_PRO "WOLFIE"
#define EIFLOW_PRO "EIFLOW"
#define MSG_PRO "MSG"
#define MOTD_PRO "MOTD"
#define ERR_PRO "ERR"
#define BYE_PRO "BYE"
#define TIME_PRO "TIME"
#define EMIT_PRO "EMIT"
#define LISTU_PRO "LISTU"
#define UTSIL_PRO "UTSIL"
#define UOFF_PRO "UOFF"
#define IAMNEW_PRO "IAMNEW"
#define HINEW_PRO "HINEW"
#define NEWPASS_PRO "NEWPASS"
#define SSAPWEN_PRO "SSAPWEN"
#define AUTH_PRO "AUTH"
#define PASS_PRO "PASS"
#define SSAP_PRO "SSAP"
#define MESSAGE_FIELD_DELIM "\r\n"
#define CARRIAGE_ENDING "\r\n\r\n"

/* Define Account Data Field Delimiters in Accounts File */
#define ACCOUNT_FIELD_DELIM " "
#define ACCOUNT_ENDING "\n"

/* Define protocol error codes and messages */
#define USERNAME_TAKEN_CODE "00"
#define USER_NOT_AVAILABLE_CODE "01"
#define BAD_PASSWORD_CODE "02"
#define SERVER_ERROR_CODE "100"
#define USERNAME_TAKEN_ERROR_MESSAGE "USER NAME TAKEN"
#define USER_NOT_AVAILABLE_ERROR_MESSAGE "USER NOT AVAILABLE"
#define BAD_PASSWORD_ERROR_MESSAGE "BAD PASSWORD"
#define SERVER_ERROR_MESSAGE "INTERNAL SERVER ERROR"

/* Define struct to hold user information */
struct user{
    char* username; // Alias of user
    unsigned char *salt;
    unsigned char *hash;
    int socket_des; // Socket descriptor for the user
    pid_t chat_win_pid; // Chat Window PID
    time_t login_time; // Time user logged into the server
    struct user *next; // Reference to next user in list
    struct user *prev; // Reference to previous user in list
};
typedef struct user user;

struct user_list {
    int max_descriptor; // Largest socket descriptor in the list
    user *list; // Address of leading user struct
    fd_set read_set;
    fd_set ready_set;


};
typedef struct user_list user_list;

/* Create reference to active user list */
extern user_list *active_user_list;
extern user_list *account_list;

/* Define output formatting strings */
#define VERBOSE_PRINT_FORMAT "\x1B[1;34m"
#define ERROR_PRINT_FORMAT "\x1B[1;31m"
#define DEFAULT_PRINT_FORMAT "\x1B[0m"

/* Define the command strings used by the server */
#define HELP_COMMAND "/help"
#define SERVER_USERS_COMMAND "/users"
#define SERVER_SHUTDOWN_COMMAND "/shutdown"
#define SERVER_ACCTS_COMMAND "/accts"

/* Define the command strings used by the client */
#define CLIENT_LISTUSERS_COMMAND "/listu"
#define CLIENT_LOGOUT_COMMAND "/logout"
#define CLIENT_TIME_COMMAND "/time"
#define CLIENT_CHAT_COMMAND "/chat"
#define CHAT_CLOSE_COMMAND "/close"

/* Define needed function prototypes */
bool is_fd_open(int fd);
bool is_password_valid(char* password);
char* create_protocol_message(char* protocol_verb, char* username, char* receiver, char* error_code, char* message_payload);
void parse_protocol_message(int client_fd, bool is_server, char *username, char *message, int vFlag, int cFlag);
void print_protocol_message(char *message, bool received);
char* read_protocol_message(int socket_des);
user_list* create_user_list();
user* create_user_struct(char* username, int socket_des);
void add_user_struct(user_list *list, user *new_user);
void destroy_user_struct(user *dead_user);
void destroy_user_list_struct(user_list *target_list, bool is_server);
bool remove_user_struct(user *target_user, user_list *target_list);
user* get_user_with_fd(int socket_des, user_list *target_list);
void print_all_users(user_list *list);
pid_t create_chat_window(int client_fd, bool is_new_user, user_list *target_list, user *target_user,
    char *current_username, char *destination_username, char *source_username, char *chat_message);
int Fork();
int Read(int fd, void* buf,size_t count);
int Write(int fd, const void *buf, size_t count);
//int Pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
//int Pthread_detach(pthread_t thread);
int Close(int fd);

/**
 * Print out the program server usage string
 */
#define USAGE_SERVER(name) do {                                                                                                \
    fprintf(stderr,                                                                                                     \
        "%s [-h|-v] PORT_NUMBER MOTD \n"                                                                              \
        "-h           Displays help menu & return EXIT_SUCCESS.\n"                                                      \
        "-v           verbose prints all incoming and outgoing protocol verbs & content.\n"                             \
        "PORT_NUMBER  Port number to listen on.\n"                                                                      \
        "MOTD         Message to display to the client when they connect.\n"                                            \
        "ACCOUNTS_FILE File containing username and password data to be loaded upon execution"                          \
        ,(name)                                                                                                         \
    );                                                                                                                  \
} while(0)

/**
 * Print out the program client usage string
 */
#define USAGE_CLIENT(name) do {                                                                                                \
    fprintf(stderr,                                                                                                     \
        "%s [-hcv] NAME SERVER_IP SERVER_PORT \n"                                                                     \
        "-h           Displays help menu & return EXIT_SUCCESS.\n"                                                      \
        "-c           requests to the server to create a new user\n"                                                    \
        "-v           verbose prints all incoming and outgoing protocol verbs & content."                               \
        "NAME         This the username to display while chatting.\n"                                                   \
        "SERVER_IP    The ip address of the server to connect to.\n"                                                    \
        "SERVER_PORT  The port to connect to.\n"                                                                        \
        ,(name)                                                                                                         \
    );                                                                                                                  \
} while(0)

#define SERVER_COMMAND_USAGE() do{                                              \
    fprintf(stdout, "%sServer Command Usage:\n"                                 \
        "/help\t\tPrints server commands and what they do.\n"                   \
        "/users\t\tPrints the users currently logged into the chat server.\n"   \
        "/shutdown\tDisconnects all users and halt the server program.\n"       \
        "/accts\tPrints a list if all user accounts and information\n"          \
        , DEFAULT_PRINT_FORMAT);                                                \
} while(0)

#define CLIENT_COMMAND_USAGE() do{                                                          \
    fprintf(stdout, "%sClient Command Usage:\n"                                               \
        "/help\t\t Prints client commands and what they do.\n"                              \
        "/listu\t\t Prints list of active users on the server.\n"                           \
        "/logout\t\tLogs off of server and exits chat client.\n"                            \
        "/time\t\tPrints the amount of time that the client has connected to the server\n"  \
        , DEFAULT_PRINT_FORMAT);                                                            \
} while(0)
#endif
