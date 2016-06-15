#include "wrap.h"

user_list *active_user_list = NULL;
user_list *account_list=NULL;
int vFlag = 0;
int cFlag = 0;
int client_fd = 0;

void sig_int_handler(int sig) {
    /* Send connnection termination message to the server */
    char *reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
    write(client_fd, reply_buffer, strlen(reply_buffer));
    if(vFlag > 0) {
        print_protocol_message(reply_buffer, false);
    }

    free(reply_buffer);

    close(client_fd);

    /* Free all active user data */
    destroy_user_list_struct(active_user_list, false);

    exit(128 + sig);
}

/**
 * Open a socket descriptor to communicate to the given server at the given port.
 * @param hostname String representation of the server address to connect to.
 * @param port String representation of the port to connect to the given server.
 * @return Returns the opened socket descriptor connected to the given server
 * listening on the given port, or -1 on error.
 */
int open_clientfd(char *hostname, char *port) {
    /* Create references to socket addr info structs */
    struct addrinfo hints, *result, *cursor;
    int clientfd;

    /* Initialize addrinfo struct with desired TCP connection settings */
    memset(&hints, 0, sizeof(struct addrinfo)); //zero it out
    hints.ai_socktype = SOCK_STREAM; /* TCP segment socket */
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;  /* For wildcard IP address on any port number */

    /* Retrieve the list of matching information structs */
    getaddrinfo(hostname, port, &hints, &result);

    /* Use for-loop to iterate through list of matching addrinfo structs and
     * attempt to open and connect a port to perform network I/O */
    for(cursor = result; cursor != NULL; cursor = cursor->ai_next) {
        /* Attempt to create a socket descriptor */
        clientfd = socket(cursor->ai_family, cursor->ai_socktype, cursor->ai_protocol);

        /* Try next potential socket if unsuccessful */
        if(clientfd < 0) {
            continue;
        }

        /* Attempt to connect the currently opened descriptor to the server address */
        int temp = connect(clientfd, cursor->ai_addr, cursor->ai_addrlen);
        if(temp != -1) {
            /* Binding succeeded, exit loop */
            break;
        }

        /* Otherwise, close current descriptor and try again */
        close(clientfd);
    }

    /* Free memory allocated to store the list of matching address information structs */
    freeaddrinfo(result);

    /* Indicate failure to open client descriptor upon exausting all results */
    if(cursor == NULL) {
        return -1;
    }

    /* Otherwise, return the client socket descriptor */
    return clientfd;
}

void login_to_server(int client_fd, char *username) {
    char *temp_buffer;

    /* Send login request to server */
    temp_buffer = create_protocol_message(WOLFIE_PRO, NULL, NULL, NULL, NULL);
    if(vFlag > 0) {
        print_protocol_message(temp_buffer, false);
    }
    write(client_fd, temp_buffer, strlen(temp_buffer));
    free(temp_buffer);

    /* Read login request confirmation from server and send login message */
    temp_buffer = read_protocol_message(client_fd);
    if(vFlag > 0) {
        print_protocol_message(temp_buffer, true);
    }
    parse_protocol_message(client_fd, false, username, temp_buffer, vFlag, cFlag);
    free(temp_buffer);

    /* Read login confirmation from the server */
    temp_buffer = read_protocol_message(client_fd);
    if(vFlag > 0) {
        print_protocol_message(temp_buffer, true);
    }
    parse_protocol_message(client_fd, false, NULL, temp_buffer, vFlag, cFlag);
    free(temp_buffer);

    /* Read password confirmation from server */
    temp_buffer = read_protocol_message(client_fd);
    if(vFlag > 0) {
        print_protocol_message(temp_buffer, true);
    }
    parse_protocol_message(client_fd, false, NULL, temp_buffer, vFlag, cFlag);
    free(temp_buffer);

    /* Read login confirmation message from server */
    temp_buffer = read_protocol_message(client_fd);
    if(vFlag > 0) {
        print_protocol_message(temp_buffer, true);
    }
    parse_protocol_message(client_fd, false, NULL, temp_buffer, vFlag, cFlag);
    free(temp_buffer);

    /* Read welcome message from server */
    temp_buffer = read_protocol_message(client_fd);
    if(vFlag > 0) {
        print_protocol_message(temp_buffer, true);
    }
    parse_protocol_message(client_fd, false, NULL, temp_buffer, vFlag, cFlag);
    free(temp_buffer);
}

////ALPHA
void start_chat(int client_fd, char *buffer, char *source_username) {
    /* Parse the chat command from the client for the needed data fields */
    char *message_tok = NULL;
    char *saveptr_message_token = NULL;
    char *reply_buffer;

    message_tok = strtok_r(buffer, " ", &saveptr_message_token);// Remove chat command
    char *destination_username = strtok_r(NULL, " ", &saveptr_message_token);
    message_tok = strtok_r(NULL, "\n", &saveptr_message_token); // Retrieve chat message to send

    if( (source_username == NULL) || (destination_username == NULL) || (strcmp(source_username, destination_username) == 0)
        || (message_tok == NULL) ) {
        fprintf(stderr, "%sInvalid chat request.%s\n",
            ERROR_PRINT_FORMAT, DEFAULT_PRINT_FORMAT);
        return;
    }

    /* Send chat initialization message to target user through server */
    reply_buffer = create_protocol_message(MSG_PRO, source_username, destination_username, NULL, message_tok);
    if(vFlag > 0) {
        print_protocol_message(reply_buffer, false);
    }
    write(client_fd, reply_buffer, strlen(reply_buffer));
    free(reply_buffer);
}

void check_chat_windows(char *username, fd_set ready_set) {
    char *temp_buffer;

    /* Use for-loop to determine which user triggered the event */
    user *temp = NULL;
    for(user *cursor = active_user_list->list; cursor != NULL; cursor = cursor->next) {
        if(FD_ISSET(cursor->socket_des, &ready_set)) {
            temp = cursor;
            break;
        }
    }

    /* When a valid client window has triggered an event */
    if(temp != NULL) {
        /* Retrieve the needed information for sending a chat message */
        int chat_fd = temp->socket_des;
        pid_t chat_pid = temp->chat_win_pid;
        char *destination_username = temp->username;

        /* Read the message from the chat window via UNIX domain socket */
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
            //if(recv(chat_fd, chat_buffer, 1, MSG_PEEK) > 0) {
                bytes_read = read(chat_fd, chat_buffer, MESSAGE_SIZE);
                current_size_counter = current_size_counter + bytes_read;
            //}
            /* Otherwise, indicate read error and fail gracefully */
            //else {
            //    fprintf(stderr, "%sFATAL READ ERROR, SOCKET DISCONNECTED screw this%s\n",
            //        ERROR_PRINT_FORMAT, DEFAULT_PRINT_FORMAT);
            //    exit(EXIT_FAILURE);
            //}
        }

        *chat_buffer_end = '\0';

        /* Check that the chat window is open */
        if(kill(chat_pid, 0) == 0) {
            /* Check for the chat close window request */
            if(strcmp(chat_buffer, CHAT_CLOSE_COMMAND) == 0) {
                /* Confirm window closure */
                write(chat_fd, "closeack\n", 9);

                /* Remove the chat window information from the user list */
                remove_user_struct(temp, active_user_list);
                close(chat_fd);
                destroy_user_struct(temp);
            }
            else {
                /* Send chat message to server socket */
                temp_buffer = create_protocol_message(MSG_PRO, username, destination_username, NULL, chat_buffer);
                write(client_fd, temp_buffer, strlen(temp_buffer));

                if(vFlag > 0) {
                    print_protocol_message(temp_buffer, false);
                }

                /* Free allocated memory */
                free(temp_buffer);
            }
        }
        /* Otherwise, the chat window is closed */
        else {
            /* Remove the chat window information from the user list */
            remove_user_struct(temp, active_user_list);
            close(chat_fd);
            destroy_user_struct(temp);
        }

        free(chat_buffer);
    }
}

int main(int argc, char* argv[]) {
    /* Create variables to hold needed values */
    int opt = 0;
    //int vFlag = 0;
    //int cFlag = 0;
    //char message_buffer[MESSAGE_SIZE] = { '\0' };
    char *temp_buffer;
    char buffer[MESSAGE_SIZE] = { '\0' };
    char *username = NULL;
    char *servername = NULL;
    char *server_port_str = NULL;
    //char *prompt = "Wolfie Chat Client> ";
    fd_set read_set, ready_set;

    /* Use getopt to parse optional arguments */
    while((opt = getopt(argc, argv, "chv")) != -1) {
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
            case 'c':
                if(cFlag == 0) {
                    cFlag++;
                }
                else {
                    fprintf(stderr, "Too many account registration argument flags\n");
                    USAGE_SERVER(argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                /* A bad option was provided. */
                USAGE_SERVER(argv[0]);
                exit(EXIT_FAILURE);
                break;
        }
    }
    if(optind < argc && argc - optind == 3) {
        username = argv[optind++];
        servername = argv[optind++];
        server_port_str = argv[optind];
    }
    /* Otherwise, fail gracefully */
    else {
        fprintf(stderr, "Too few positional args.\n");
        USAGE_CLIENT(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Attempt to open a client connection to the server */
    client_fd = open_clientfd(servername, server_port_str);

    /* Exit upon connection failure */
    if(client_fd < 0) {
        printf("Connection to server failed. Exiting...\n");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    /* Attempt to login to server */
    login_to_server(client_fd, username);

    /* Initialize selection set to multiplex over input descriptors */
    //FD_SET(STDIN_FILENO, &read_set);
    //FD_SET(client_fd, &read_set);
    FD_ZERO(&read_set);

    /* Create user list to manage the chat windows with other clients */
    active_user_list = create_user_list();

    /* Register signal handler for keyboard interrupt */
    signal(SIGINT, sig_int_handler);

    /* Prompt client for message for server using while-loop */
    while(1) {
        /* Update descriptor set to check for I/O mux */
        read_set = active_user_list->read_set;
        int max_descriptor = (active_user_list->list == NULL) ? client_fd : (active_user_list->max_descriptor);
        FD_SET(STDIN_FILENO, &read_set);
        FD_SET(client_fd, &read_set);
        ready_set = read_set;

        /* Wait for event on the file descriptor */
        int select_result = select(max_descriptor+1, &ready_set, NULL, NULL, NULL);

        /* Return to the restart the I/O mux on error */
        if(select_result < 0) {
            fprintf(stderr, "%s%s%s\n", ERROR_PRINT_FORMAT, strerror(errno), DEFAULT_PRINT_FORMAT);
            continue;
        }
        /* Event was on STDIN */
        if(FD_ISSET(STDIN_FILENO, &ready_set)) {
            /* Read input from user */
            fgets(buffer, MESSAGE_SIZE-1, stdin);

            /* Set trailing newline to null byte */
            buffer[strlen(buffer) - 1] = '\0';

            /* Exit the client when LOGOUT command is detected */
            if(strcmp(buffer, CLIENT_LOGOUT_COMMAND) == 0) {
                temp_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
                write(client_fd, temp_buffer, strlen(temp_buffer));
                if(vFlag > 0) {
                    print_protocol_message(temp_buffer, false);
                }
                free(temp_buffer);
            }
            /* Prompt server for connection duration when TIME command is detected */
            else if(strcmp(buffer, CLIENT_TIME_COMMAND) == 0) {
                /* Send session time request to server */
                temp_buffer = create_protocol_message(TIME_PRO, NULL, NULL, NULL, NULL);
                write(client_fd, temp_buffer, strlen(temp_buffer));
                if(vFlag > 0) {
                    print_protocol_message(temp_buffer, false);
                }
                free(temp_buffer);
            }
            /* Prompt server for list of active users */
            else if(strcmp(buffer, CLIENT_LISTUSERS_COMMAND) == 0) {
                /* Send active users list request to server */
                temp_buffer = create_protocol_message(LISTU_PRO, NULL, NULL, NULL, NULL);
                write(client_fd, temp_buffer, strlen(temp_buffer));
                if(vFlag > 0) {
                    print_protocol_message(temp_buffer, false);
                }
                free(temp_buffer);
            }
            /* Prompt to start chat with another user on the chat server */
            else if(strlen(buffer) > 5 && strncmp(buffer, CLIENT_CHAT_COMMAND, 5) == 0) {
                /* Parse entered chat message for needed data fields */
                buffer[strlen(buffer)] = '\n';
                start_chat(client_fd, buffer, username);
            }
            /* Print command usage for client */
            else if(strcmp(buffer, HELP_COMMAND) == 0) {
                CLIENT_COMMAND_USAGE();
            }
            else {
                /* Prompt user for input again before sending to server */
                fprintf(stderr, "%sInput \"%s\" is not a valid client command.%s\n",
                    ERROR_PRINT_FORMAT, buffer, DEFAULT_PRINT_FORMAT);
            }

            memset(buffer, 0, strlen(buffer));
        }
        /* Event was on network socket */
        else if(FD_ISSET(client_fd, &ready_set)) {
            /* Read message from server */
            temp_buffer = read_protocol_message(client_fd);
            if(vFlag > 0) {
                print_protocol_message(temp_buffer, true);
            }

            /* Parse the server message */
            parse_protocol_message(client_fd, false, username, temp_buffer, vFlag, cFlag);
            free(temp_buffer);
        }

        /* Otherwise, event was from chat window process */
        else {
            check_chat_windows(username, ready_set);
        }
    }

    close(client_fd); // close the socket

    return EXIT_SUCCESS;
}
