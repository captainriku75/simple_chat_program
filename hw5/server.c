#include "wrap.h"

//void *thread(void *vargp);
/* Create reference for login message to send to clients */
char *MOTD = NULL;
pthread_t communication_thread_id = 0;
int vFlag = 0;
int cFlag = 0;
char* account_file = NULL;

/* Create the active user list */
user_list *active_user_list = NULL;
user_list *account_list = NULL;

void sig_int_handler(int sig){
    /* Free space allocated for MOTD */
    free(MOTD);

    /* Send connnection termination messages to all active users */
    char *reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
    for(user *cursor = active_user_list->list; cursor != NULL; cursor = cursor->next) {
        write((cursor->socket_des), reply_buffer, strlen(reply_buffer));
        if(vFlag > 0) {
            print_protocol_message(reply_buffer, false);
        }
    }
    free(reply_buffer);

    /* Free all active user data */
    destroy_user_list_struct(active_user_list, true);

    exit(128 + sig);
}

/**
 * Open a socket descriptor for listening to incoming client connection requests.
 * @param port String representation of the port to bind the created listening socket to.
 * @return Returns the opened socket descriptor bound to the given port, or -1 on error.
 */
int open_listenfd(char *port) {
    /* Create references to socket addr info structs */
    struct addrinfo hints, *result, *cursor;
    int listenfd;
    int optval = 1;

    /* Initialize addrinfo struct with desired TCP connection settings */
    memset(&hints, 0, sizeof(struct addrinfo)); //zero it out
    hints.ai_family = AF_INET;    /* Allow IPv4 */
    hints.ai_socktype = SOCK_STREAM; /* TCP segment socket */
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV;  /* For wildcard IP address on any port number */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    /* Retrieve the list of matching information structs */
    getaddrinfo(NULL, port, &hints, &result);

    /* Use for-loop to iterate through list of matching addrinfo structs and
     * attempt to open and bind a port to perform network I/O */
    for(cursor = result; cursor != NULL; cursor = cursor->ai_next) {
        /* Attempt to create a socket descriptor */
        listenfd = socket(cursor->ai_family, cursor->ai_socktype, cursor->ai_protocol);

        /* Try next potential socket if unsuccessful */
        if(listenfd < 0) {
            continue;
        }

        /* Reuse socket if already in use */
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(int));

        /* Attempt to bind the currently opened descriptor to the address */
        int temp = bind(listenfd, cursor->ai_addr, cursor->ai_addrlen);
        if(temp == 0) {
            /* Binding succeeded, exit loop */
            break;
        }
        fprintf(stderr, "%s\n", strerror(errno));
        /* Otherwise, close current descriptor and try again */
        close(listenfd);
    }

    /* Free memory allocated to store the list of matching address information structs */
    freeaddrinfo(result);

    /* Indicate failure to open listen descriptor upon exausting all results */
    if(cursor == NULL) {
        return -1;
    }

    /* Attempt to set the socket to listen for incoming connections */
    if(listen(listenfd, LISTEN_BACKLOG) < 0) {
        /* Close socket descriptor and indicate failure upon failure */
        close(listenfd);
        return -1;
    }

    /* Otherwise, return the listening socket descriptor */
    return listenfd;
}

void exit_server(int return_code, int fd) {
    /*close the socket*/
    close(fd);

    /* Free memory holding message of the day */
    free(MOTD);

    /* Send connnection termination messages to all active users */
    char *reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
    for(user *cursor = active_user_list->list; cursor != NULL; cursor = cursor->next) {
        write((cursor->socket_des), reply_buffer, strlen(reply_buffer));
        if(vFlag > 0) {
            print_protocol_message(reply_buffer, false);
        }
    }
    free(reply_buffer);

    /* Free all active user data */
    destroy_user_list_struct(active_user_list, true);

    /* Save the account list */
    FILE *fp = (account_file != NULL) ? fopen(account_file, "w") : fopen("account_list.txt", "w");

    /* Use for-loop to save the account data to file */
    char *account_buffer = NULL;
    for(user *cursor = account_list->list; cursor != NULL; cursor = cursor->next) {
        /* Build data buffer for current account data */
        account_buffer = calloc(1, (strlen(cursor->username) + (2 * strlen(ACCOUNT_FIELD_DELIM)) + strlen(ACCOUNT_ENDING) + 40) );
        strcat(account_buffer, cursor->username);
        strcat(account_buffer, ACCOUNT_FIELD_DELIM);
        memcpy( (account_buffer + strlen(cursor->username) + strlen(ACCOUNT_FIELD_DELIM)), cursor->salt, 8);
        memcpy( ((account_buffer + strlen(cursor->username) + strlen(ACCOUNT_FIELD_DELIM)) + 8),
            ACCOUNT_FIELD_DELIM, strlen(ACCOUNT_FIELD_DELIM));
        memcpy( (account_buffer + strlen(cursor->username) + (2 * strlen(ACCOUNT_FIELD_DELIM)) + 8), cursor->hash, 32);
        memcpy( (account_buffer + strlen(cursor->username) + (2 * strlen(ACCOUNT_FIELD_DELIM)) + 40),
            ACCOUNT_ENDING, strlen(ACCOUNT_ENDING));

        /* Write account data to file */
        fwrite(account_buffer, 1, (strlen(cursor->username) +
            (2 * strlen(ACCOUNT_FIELD_DELIM)) + strlen(ACCOUNT_ENDING) + 40), fp);
        free(account_buffer);
    }

    /* Destroy the accounts list */
    destroy_user_list_struct(account_list, true);

    exit(EXIT_SUCCESS);
}

void log_off_client(int client_fd) {
    write(client_fd, "Good bye client.", 16);

    /* Get reference to user logging out */
    user *temp = get_user_with_fd(client_fd, active_user_list);

    /* Free up the user name in the list */
    remove_user_struct(temp, active_user_list);
    destroy_user_struct(temp);

    /* Close the client descriptor */
    close(client_fd);
    printf("Conversation with current user finished.\nConnection closed.\n");
}

bool log_client_into_server(int client_fd, int vFlag) {
    char *temp_buffer;

    /* Read the login request message from the client */
    temp_buffer = read_protocol_message(client_fd);
    if(vFlag > 0) {
        print_protocol_message(temp_buffer, true);
    }
    parse_protocol_message(client_fd, true, NULL, temp_buffer, vFlag, cFlag);
    free(temp_buffer);

    /* Read the client identification message from the client */
    temp_buffer = read_protocol_message(client_fd);
    if(vFlag > 0) {
        print_protocol_message(temp_buffer, true);
    }
    parse_protocol_message(client_fd, true, NULL, temp_buffer, vFlag, cFlag);
    free(temp_buffer);

    if(is_fd_open(client_fd)) {
        /* Read the password message from the client */
        temp_buffer = read_protocol_message(client_fd);
        if(vFlag > 0) {
            print_protocol_message(temp_buffer, true);
        }
        parse_protocol_message(client_fd, true, NULL, temp_buffer, vFlag, cFlag);
        free(temp_buffer);

        if(is_fd_open(client_fd) && get_user_with_fd(client_fd, active_user_list) != NULL) {
            /* Setup code to sleep for 100 milliseconds */
            struct timespec tp;
            tp.tv_sec = 0;
            tp.tv_nsec = 100000000;
            nanosleep(&tp, NULL);

            /* Send the message of the day to the cliet on successful login */
            temp_buffer = create_protocol_message(MOTD_PRO, NULL, NULL, NULL, MOTD);
            if(vFlag > 0) {
                print_protocol_message(temp_buffer, false);
            }
            write(client_fd, temp_buffer, strlen(temp_buffer));
            free(temp_buffer);

            return true;
        }
        else {
            return false;
        }
    }
    else {
        return false;
    }
}

/* Initial call to start the communicatioh thread */
void *communication_thread(void *args) {
    char* temp_buffer;
    struct timeval tv;

    /* Detach current thread from calling thread */
    int detach_status = pthread_detach(pthread_self());
    if(detach_status != 0) {
        fprintf(stderr, "%sIssue detaching login thread from accept thread.%s\n",
            ERROR_PRINT_FORMAT, DEFAULT_PRINT_FORMAT);
            communication_thread_id = 0;
            return NULL;
    }

    /* Use while-loop to multiplex over all active user file descriptors */
    while(1) {
        /* Update the struct holding the timeout definition */
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        /* Update the set of descriptors to multiplex over */
        active_user_list->ready_set = active_user_list->read_set;

        /* Wait for event on the file descriptor */
        int select_result = select((active_user_list->max_descriptor)+1, &(active_user_list->ready_set), NULL, NULL, &tv);

        /* Return to the restart the I/O mux on error */
        if(select_result < 0) {
            fprintf(stderr, "%s%s%s\n", ERROR_PRINT_FORMAT, strerror(errno), DEFAULT_PRINT_FORMAT);
            continue;
        }
        /* Otherwise, determine which descriptor triggered I/O event */
        else {
            /* Use for-loop to determine which user triggered the event */
            user *temp = NULL;
            for(user *cursor = active_user_list->list; cursor != NULL; cursor = cursor->next) {
                if(FD_ISSET(cursor->socket_des, &(active_user_list->ready_set))) {
                    temp = cursor;
                    break;
                }
            }

            /* When a valid user has triggered an event */
            if(temp != NULL) {
                int client_fd = temp->socket_des;

                /* Read client input from the connected socket */
                temp_buffer = read_protocol_message(client_fd);

                if(vFlag > 0) {
                    print_protocol_message(temp_buffer, true);
                }

                /* Parse the message sent from the client */
                parse_protocol_message(client_fd, true, NULL, temp_buffer, vFlag, cFlag);

                /* Reset buffer */
                free(temp_buffer);
            }
        }

        /* Check if there are active users */
        if(active_user_list->list == NULL) {
            /* Exit the communication thread when there are no active users */
            communication_thread_id = 0;
            return NULL;
        }
    }
}

/* Initial call to start login process from new thread */
void *login_thread(void *args) {
    /* Retrieve new client socket descriptor */
    int client_fd = *((int *) args);
    free(args);

    /* Detach current thread from calling thread */
    int detach_status = pthread_detach(pthread_self());
    if(detach_status != 0) {
        fprintf(stderr, "%sIssue detaching login thread from accept thread.%s\n",
            ERROR_PRINT_FORMAT, DEFAULT_PRINT_FORMAT);
            return NULL;
    }

    /* Attempt to log new client onto server */
    bool login_succeed = log_client_into_server(client_fd, vFlag);
    if(login_succeed) {
        /* Spawn communication thread if it did not exist */
        if(active_user_list->list != NULL && communication_thread_id == 0) {
            pthread_create(&communication_thread_id, NULL, communication_thread, NULL);
        }
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    int opt = 0;
    char* port_num_str; // reference for listening port
    int listen_fd = 0;
    int *client_fd;
    FILE *fp = 0;
    socklen_t clientlen = 0;
//    char *temp_buffer;
    char buffer[BUFFER_SIZE] = { '\0' };
    struct sockaddr_storage client_addr;
    fd_set read_set, ready_descriptors; // Set of descriptors ready for reading
    pthread_t tid;
    //make sure the port number is there

    // handles getting the optional args
    while((opt = getopt(argc, argv, "hv")) != -1) {
        switch(opt) {
            case 'h':
                /* The help menu was selected */
                USAGE_SERVER(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                if(vFlag == 0) {
                    vFlag++;
                }
                else {
                    fprintf(stderr, "Too many verbose argument flags\n");
                    USAGE_SERVER(argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                /* A bad option was provided. */
                fprintf(stderr, "BAD ARG -%c\n", optopt);
                USAGE_SERVER(argv[0]);
                exit(EXIT_FAILURE);
                break;
        }
    }
    /* Retrieve positional arguments */
    if(optind< argc && argc-optind == 3) {
        port_num_str = argv[optind++];
        MOTD = calloc(1, strlen(argv[optind]));
        strncpy(MOTD, argv[optind], strlen(argv[optind]));
        optind++;
        account_file = argv[optind];
    }
    else if(optind < argc && argc - optind == 2) {
        port_num_str = argv[optind++];
        MOTD = calloc(1, strlen(argv[optind]));
        strncpy(MOTD, argv[optind], strlen(argv[optind]));
    }
    else {
        fprintf(stderr, "Invalid number of few positional args.\n");
        USAGE_SERVER(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Catch SIGINT */
    signal(SIGINT, sig_int_handler);

    /* Open socket descriptor to listen for connection requests */
    if((listen_fd = open_listenfd(port_num_str)) < 0) {
        fprintf(stderr, "Could not open socket connection.\n");
        exit(EXIT_FAILURE);
    }

    /* Clear all descriptors in selection set for descriptor mux */
    FD_ZERO(&read_set);

    /* Set both stdin and the listen socket descriptor for I/O mux */
    FD_SET(STDIN_FILENO, &read_set);
    FD_SET(listen_fd, &read_set);

    /* Create the active users list */
    active_user_list = create_user_list();
    account_list = create_user_list();

    /* Read accounts from account file when given */
    if(account_file != NULL) {
        fp = fopen(account_file, "r");
        char* buffer = calloc(1, MESSAGE_SIZE);
        int max_space_counter = MESSAGE_SIZE;
        int current_size_counter = 0;
        int bytes_read = 0;

        if(buffer == NULL) {
            fprintf(stderr, "failed to calloc buffer for read start\n");
            exit(EXIT_FAILURE);
        }

        /* Read from accounts file using while-loop */
        while(!feof(fp)) {
            if(current_size_counter >= ( max_space_counter / 2 ) ) {
                max_space_counter = max_space_counter * 2;
                buffer = realloc(buffer, max_space_counter);
                if(buffer == NULL) {
                    fprintf(stderr, "failed to realloc buffer\n");
                    exit(EXIT_FAILURE);
                }
            }

            bytes_read = fread(buffer, 1, MESSAGE_SIZE, fp);
            current_size_counter = current_size_counter + bytes_read;
       }

       char *cursor = buffer;
       int len = 0;
       while(cursor != NULL && len < current_size_counter) {
           /* Retrieve current username */
           char *temp_buff = calloc(1, MESSAGE_SIZE);
           int i = 0;
           while(*cursor != ' ' && len < current_size_counter) {
               *(temp_buff+i) = *cursor;
               cursor++;
               len++;
               i++;
           }
           user *temp = create_user_struct(temp_buff, 0);
           add_user_struct(account_list, temp);
           free(temp_buff);

           /* Retrieve current salt */
           temp_buff = calloc(1, 8);
           cursor++;
           len++;
           i = 0;
           while(i < 8 && len < current_size_counter) {
               *(temp_buff+i) = *cursor;
               len++;
               i++;
               cursor++;
           }
           temp->salt = (unsigned char *) temp_buff;

           /* Retrieve Hash */
           temp_buff = calloc(1, 32);
           cursor++;
           len++;
           i = 0;
           while(i < 32 && len < current_size_counter) {
               *(temp_buff+i) = *cursor;
               len++;
               i++;
               cursor++;
           }
           temp->hash = (unsigned char *) temp_buff;
           cursor++;
           len++;
       }
    }

    /* Indicate to local server user that server is ready */
    printf("%sReady to serve...\n", DEFAULT_PRINT_FORMAT);
    printf("%slistening on port %s\n",DEFAULT_PRINT_FORMAT, port_num_str);
    fflush(stdout);

    /* Use while-loop to check for client connections and handle local input */
    while(1) {
        /* Update descriptor set to check for I/O mux */
        ready_descriptors = read_set;

        /* Wait for event on the file descriptor */
        int select_result = select(listen_fd+1, &ready_descriptors, NULL, NULL, NULL);

        /* Return to the restart the I/O mux on error */
        if(select_result < 0) {
            fprintf(stderr, "%s%s%s\n", ERROR_PRINT_FORMAT, strerror(errno), DEFAULT_PRINT_FORMAT);
            continue;
        }
        /* Event was from local stdin */
        if(FD_ISSET(STDIN_FILENO, &ready_descriptors)) {
            /* Echo text typed into server locally */
            memset(buffer, 0, sizeof(buffer));
            fgets(buffer, BUFFER_SIZE-1, stdin);
            buffer[strlen(buffer) - 1] = '\0';

            /* Check for SHUTDOWN command */
            if(strcmp(buffer, SERVER_SHUTDOWN_COMMAND) == 0) {
                printf("%sExiting server...\n", DEFAULT_PRINT_FORMAT);
                break;
            }
            /* Check for USERS command  */
            else if(strcmp(buffer, SERVER_USERS_COMMAND) == 0) {
                /* Print all active users */
                print_all_users(active_user_list);
            }
            /* Check for ACCTS command */
            else if(strcmp(buffer, SERVER_ACCTS_COMMAND) == 0) {
                /* Print all user accounts */
                print_all_users(account_list);
            }
            /* Check for HELP command */
            else if(strcmp(buffer, HELP_COMMAND) == 0) {
                /* Print the server command usage */
                SERVER_COMMAND_USAGE();
            }
            /* Otherwise, input is not valid server command */
            else {
                fprintf(stderr, "%sInput \"%s\" is not a valid server command.%s\n",
                    ERROR_PRINT_FORMAT, buffer, DEFAULT_PRINT_FORMAT);
            }
        }
        /* When the server receives data from the listen socket descriptor */
        if(FD_ISSET(listen_fd, &ready_descriptors)) {
            /* Prepare the socket address struct for connection to the client */
            clientlen = sizeof(struct sockaddr_storage);

            /* Allocate memory to store descriptor to connect to client */
            client_fd = calloc(1, sizeof(int));

            /* Attempt to accept the connection */
            if((*client_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &clientlen)) < 0) {
                free(client_fd);
                continue;
            }
            /* Communicate with the client when the accept is successful */
            else {
                /* Attempt to log client into server */
                pthread_create(&tid, NULL, login_thread, (void*) client_fd);
            }
        }
    }

    exit_server(EXIT_SUCCESS, listen_fd);
}
