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

/* Define output formatting strings */
#define VERBOSE_PRINT_FORMAT "\x1B[1;34m"
#define ERROR_PRINT_FORMAT "\x1B[1;31m"
#define DEFAULT_PRINT_FORMAT "\x1B[0m"

#define CHAT_CLOSE_COMMAND "/close"
#define MESSAGE_SIZE 1024

int chat_fd = 0;

bool is_fd_open(int fd) {
    /* Check if client login was unsuccessful */
    if(fcntl(fd, F_GETFL) < 0 && errno == EBADF) {
        return false;
    }
    else {
        return true;
    }
}

void sig_int_hup_handler(int sig) {
    /* Indicate chat window closing */
    write(chat_fd, "/close\n", 7);

    /* Wait for decouple confirmation */
    char *chat_buffer = calloc(1, MESSAGE_SIZE);
    char *chat_buffer_end = NULL;
    int max_space_counter = MESSAGE_SIZE;
    int current_size_counter = 0;
    int bytes_read = 0;
    while((chat_buffer_end = strstr(chat_buffer, "\n")) == NULL) {
        /* Grow buffer as needed */
        if(current_size_counter >= ( max_space_counter / 2 ) ) {
            max_space_counter = max_space_counter * 2;
            chat_buffer = realloc(chat_buffer, max_space_counter);
            if(chat_buffer == NULL) {
                fprintf(stderr, "failed to realloc buffer\n");
                exit(EXIT_FAILURE);
            }
        }

        /* Read from the socket when there is data to read */
        int test = recv(chat_fd, chat_buffer, 1, MSG_PEEK);
        if(test > 0) {
            bytes_read = read(chat_fd, chat_buffer, MESSAGE_SIZE);
            current_size_counter = current_size_counter + bytes_read;
        }
        /* Otherwise, indicate read error and fail gracefully */
        else {
            fprintf(stderr, "%sFATAL READ ERROR, SOCKET DISCONNECTED: %s%s\n",
                ERROR_PRINT_FORMAT, strerror(errno), DEFAULT_PRINT_FORMAT);
            fgets(chat_buffer, 2, stdin);
            exit(EXIT_FAILURE);
        }
    }

    *chat_buffer_end = '\0';

    free(chat_buffer);

    exit(128 + sig);
}

int main(int argc, char* argv[]) {
    char* client_num = argv[1];
    char *end_ptr = NULL;
    char buffer[MESSAGE_SIZE] = { '\0' };
    errno = 0;
    fd_set rfds;
    int retval;
    chat_fd = strtol(client_num, &end_ptr, 10);
    if ((errno != 0 && chat_fd == 0)) {
        perror("strtol");
        exit(EXIT_FAILURE);
    }

    if (end_ptr == client_num) {
        fprintf(stderr, "No digits were found\n");
        exit(EXIT_FAILURE);
    }

    //printf("Ready to receive chat messages... from fd: %d\n", chat_fd);
    //signal(SIGSEGV, sig_segv_handler);

    if(!is_fd_open(chat_fd)) {
        char chat_buffer[2] = {'\0'};
        fprintf(stderr, "%sSOCKET CLOED, CANNOT RECEIVE%s\n", ERROR_PRINT_FORMAT, DEFAULT_PRINT_FORMAT);
        fgets(chat_buffer, 2, stdin);
        exit(EXIT_FAILURE);
    }

    /* Register signal handler for keyboard interrupt */
    signal(SIGINT, sig_int_hup_handler);
    signal(SIGHUP, sig_int_hup_handler);

    while(1) {
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(chat_fd, &rfds);
        retval = select(chat_fd + 1, &rfds, NULL, NULL, NULL);
        /* Invalid event */
        if(retval < 0) {
            fprintf(stderr, "%s%s%s\n", ERROR_PRINT_FORMAT, strerror(errno), DEFAULT_PRINT_FORMAT);
            continue;
        }
        if(FD_ISSET(STDIN_FILENO, &rfds)) {
            fgets(buffer, MESSAGE_SIZE-1, stdin);

            /* Set trailing newline to null byte */
            buffer[strlen(buffer) - 1] = '\0';

            if(strcmp(buffer, CHAT_CLOSE_COMMAND) == 0) {
                /* Notify client window of chat close command */
                buffer[strlen(buffer)] = '\n';
                write(chat_fd, buffer, strlen(buffer));

                /* Wait for decouple confirmation */
                char *chat_buffer = calloc(1, MESSAGE_SIZE);
                char *chat_buffer_end = NULL;
                int max_space_counter = MESSAGE_SIZE;
                int current_size_counter = 0;
                int bytes_read = 0;
                while((chat_buffer_end = strstr(chat_buffer, "\n")) == NULL) {
                    /* Grow buffer as needed */
                    if(current_size_counter >= ( max_space_counter / 2 ) ) {
                        max_space_counter = max_space_counter * 2;
                        chat_buffer = realloc(chat_buffer, max_space_counter);
                        if(chat_buffer == NULL) {
                            fprintf(stderr, "failed to realloc buffer\n");
                            exit(EXIT_FAILURE);
                        }
                    }

                    /* Read from the socket when there is data to read */
                    int test = recv(chat_fd, chat_buffer, 1, MSG_PEEK);
                    if(test > 0) {
                        bytes_read = read(chat_fd, chat_buffer, MESSAGE_SIZE);
                        current_size_counter = current_size_counter + bytes_read;
                    }
                    /* Otherwise, indicate read error and fail gracefully */
                    else {
                        fprintf(stderr, "%sFATAL READ ERROR, SOCKET DISCONNECTED: %s%s\n",
                            ERROR_PRINT_FORMAT, strerror(errno), DEFAULT_PRINT_FORMAT);
                        fgets(chat_buffer, 2, stdin);
                        exit(EXIT_FAILURE);
                    }
                }

                *chat_buffer_end = '\0';
                if(strcmp(chat_buffer, "closeack") == 0) {
                    free(chat_buffer);
                    break;
                }
                else {
                    printf("CLOSURE DENIED\n");
                }

                free(chat_buffer);
            }

            buffer[strlen(buffer)] = '\n';

            if (write(chat_fd, buffer, strlen(buffer)) != strlen(buffer)) {
                fprintf(stderr, "Write failed in chat.c\n");
            }
            else {
                //fprintf(stderr, "Write was successful!\n");
            }

            memset(buffer, 0, strlen(buffer));
        }
        if(FD_ISSET(chat_fd, &rfds)) {
            /* Read the message from the client process via UNIX domain socket */
            char *chat_buffer = calloc(1, MESSAGE_SIZE);
            char *chat_buffer_end = NULL;
            int max_space_counter = MESSAGE_SIZE;
            int current_size_counter = 0;
            int bytes_read = 0;
            while((chat_buffer_end = strstr(chat_buffer, "\n")) == NULL) {
                /* Grow buffer as needed */
                if(current_size_counter >= ( max_space_counter / 2 ) ) {
                    max_space_counter = max_space_counter * 2;
                    chat_buffer = realloc(chat_buffer, max_space_counter);
                    if(chat_buffer == NULL) {
                        fprintf(stderr, "failed to realloc buffer\n");
                        exit(EXIT_FAILURE);
                    }
                }

                /* Read from the socket when there is data to read */
                int test = recv(chat_fd, chat_buffer, 1, MSG_PEEK);
                if(test > 0) {
                    bytes_read = read(chat_fd, chat_buffer, MESSAGE_SIZE);
                    current_size_counter = current_size_counter + bytes_read;
                }
                /* Otherwise, indicate read error and fail gracefully */
                else {
                    fprintf(stderr, "%sFATAL READ ERROR, SOCKET DISCONNECTED: %s%s\n",
                        ERROR_PRINT_FORMAT, strerror(errno), DEFAULT_PRINT_FORMAT);
                    fgets(chat_buffer, 2, stdin);
                    exit(EXIT_FAILURE);
                }
            }

            *chat_buffer_end = '\0';

            if(strcmp(chat_buffer, CHAT_CLOSE_COMMAND) == 0) {
                write(chat_fd, "closeack\n", 9);
                free(chat_buffer);
                break;
            }
            else {
                printf("%s\n", chat_buffer);
                fflush(stdout);
            }

            free(chat_buffer);
        }
    }

    close(chat_fd);

    return EXIT_SUCCESS;
}
