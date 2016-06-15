#include "wrap.h"

pid_t Fork(void) {
    pid_t pid;

    /* Create child process */
    if((pid = fork()) < 0) {
        /* Print error in forking when pid is negative */
        fprintf(stderr, "Fork error %d \n", errno);
        exit(0);
    }

    return pid;
}
bool is_password_valid(char* password) {
    int len = 0;
    int upper_flag = 0;
    int symbol_flag = 0;
    int num_flag = 0;
    char* cursor = password;

    while((len < strlen(password)) && ((symbol_flag < 1) || (num_flag < 1) || (upper_flag < 1)) ) {
        if((*cursor >= 65) && (*cursor <= 90)) {
            upper_flag++;
        }
        else if((*cursor >= 48) && (*cursor <= 57)) {
            num_flag++;
        }
        else if(((*cursor >= 33) && (*cursor <= 47)) || ((*cursor >= 58)&&(*cursor <= 64))
        || ((*cursor >= 92) && (*cursor <= 96)) || ((*cursor >= 123) && (*cursor <= 126))) {
            symbol_flag++;
        }
        else{
            // Lowercase letter, do nothing
        }

        /* Increment counters over counters */
        len++;
        cursor++;
    }

    /* Return valuse based on constraints being met */
    if( (strlen(password) >= 5) && (symbol_flag > 0) && (num_flag > 0) && (upper_flag > 0) ) {
        return true;
    }

    return false;
}

int Read(int fd, void* buf,size_t count)
{
  int ans=read(fd, buf, count);
  if(ans<0)
  {
    fprintf(stderr, "read: %s\n", gai_strerror(ans));
    exit(1);
  }
  return ans;
}
int Write(int fd, const void *buf, size_t count)
{
  int ans=write(fd, buf, count);
  if(ans<0)
  {
    fprintf(stderr, "write: %s\n", gai_strerror(ans));
    exit(1);
  }
  return ans;
}

bool is_fd_open(int fd) {
    /* Check if client login was unsuccessful */
    if(fcntl(fd, F_GETFL) < 0 && errno == EBADF) {
        return false;
    }
    else {
        return true;
    }
}

user_list* create_user_list(){
    /* Create new user_list struct */
    user_list *new_list = calloc(1, sizeof(user_list));

    /* Initialize new user_list struct data */
    new_list->max_descriptor = 0;
    new_list->list = NULL;
    FD_ZERO(&(new_list->ready_set));
    FD_ZERO(&(new_list->read_set));

    return new_list;
}

user* create_user_struct(char* username, int socket_des) {
    /* Create new user struct */
    user *new_user = calloc(1, sizeof(user));

    /* Initialize the new user struct data */
    new_user->username = calloc(1, strlen(username));
    strncpy(new_user->username, username, strlen(username));
    new_user->socket_des = socket_des;
    new_user->login_time = time(NULL);
    return new_user;
}

void add_user_struct(user_list *list, user *new_user) {
    /* Retrieve the starting entry of the list */
    user *cursor = list->list;

    if(cursor == NULL) {
        /* Store new user at start of empty list */
        list->list = new_user;
    }
    else {
        /* Otherwise, store user at the end of the active user list */
        while(cursor->next != NULL) {
            cursor = cursor->next;
        }
        cursor->next = new_user;
        new_user->prev = cursor;
    }

    /* Update the set of ready descriptors */
    FD_SET(new_user->socket_des, &(list->read_set));

    /* Update the maximum socket descriptor if necessary */
    int new_max = 0;
    for(user *temp = list->list; temp != NULL; temp = temp->next) {
        if(temp->socket_des > new_max) {
            new_max = temp->socket_des;
        }
    }
    list->max_descriptor = new_max;
}

void destroy_user_struct(user *dead_user) {
    /* Free dynamic memory in fields of user struct */
    free(dead_user->username);

    if(dead_user->salt != NULL) {
        free(dead_user->salt);
    }

    if(dead_user->hash != NULL) {
        free(dead_user->hash);
    }

    /* Free memory allocated for user struct */
    free(dead_user);
}

void destroy_user_list_struct(user_list *target_list, bool is_server) {
    if(target_list == NULL) {
        return;
    }

    /* Free all user structs in the target list */
    user *cursor = target_list->list;
    while (cursor != NULL) {
        user *temp = cursor;
        cursor = cursor->next;

        remove_user_struct(temp, target_list);

        /* Terminate the chat windows if it is a client user list */
        if(!is_server) {
            /* Send the closing request to the chat windows */
            write(temp->socket_des, "/close\n", 7);

            /* Wait for ack from chat window */
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
                int test = recv(temp->socket_des, chat_buffer, 1, MSG_PEEK);
                if(test > 0) {
                    bytes_read = read(temp->socket_des, chat_buffer, MESSAGE_SIZE);
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

            /* Kill process if ACK not received */
            if(strcmp(chat_buffer, "closeack") != 0) {
                kill(temp->chat_win_pid, 3);
            }

            free(chat_buffer);
            close(temp->socket_des);
        }
        destroy_user_struct(temp);
    }

    /* Free memory allocated for the user_list struct */
    free(target_list);
}

void print_all_users(user_list *list) {
    printf("%s------------------------\n"
             "|         USERS        |\n"
             "------------------------\n", DEFAULT_PRINT_FORMAT);
    /* Use while-loop to print all active users when list is non-empty */
    user *cursor = list->list;
	if(cursor == NULL) {
        printf("%s|        (none)        |\n", DEFAULT_PRINT_FORMAT);
    }
    else {
        while(cursor != NULL) {
            printf("%s| %20s |\n", DEFAULT_PRINT_FORMAT, cursor->username);
            cursor = cursor->next;
        }
    }

    printf("%s------------------------\n", DEFAULT_PRINT_FORMAT);
}

user* get_user_with_fd(int socket_des, user_list *target_list) {
    /* Indicate when descriptor is a standard one or list is empty */
    if(socket_des < 3 || target_list->list == NULL) {
        errno = EINVAL;
        return NULL;
    }

    /* Start search from the beginning of the user list */
    user *cursor = target_list->list;
    while(cursor != NULL) {
        /* Stop search when matching user is found */
        if(cursor->socket_des == socket_des) {
            break;
        }

        /* Otherwise, check next user in list */
        cursor = cursor->next;
    }

    return cursor;
}

user* get_user_with_username(char *target_username, user_list *target_list) {
    /* Indicate when descriptor is a standard one or list is empty */
    if(target_username == NULL || target_list->list == NULL) {
        errno = EINVAL;
        return NULL;
    }

    /* Start search from the beginning of the user list */
    user *cursor = target_list->list;
    while(cursor != NULL) {
        /* Stop search when matching user is found */
        if(strcmp(target_username, cursor->username) == 0) {
            break;
        }

        /* Otherwise, check next user in list */
        cursor = cursor->next;
    }

    return cursor;

}

bool remove_user_struct(user *target_user, user_list *target_list) {
    /* Indicate invalid NULL pointer */
    if(target_user == NULL) {
        errno = EINVAL;
        return false;
    }

    bool removed = false;

    /* Retrieve pointers to next and previous references in list */
    user *next = target_user->next;
    user *prev = target_user->prev;

    /* When target is only user in list */
    if(next == NULL && prev == NULL) {
        target_list->list = NULL;
        removed = true;
    }
    /* When target is at the start of the list */
    else if(next != NULL && prev == NULL) {
        target_list->list = next;
        next->prev = NULL;
        target_user->next = NULL;
        removed = true;
    }
    /* When target is at the end of the list */
    else if(next == NULL && prev != NULL) {
        prev->next = NULL;
        target_user->next = NULL;
        removed = true;
    }
    /* When the target is in the middle of the list */
    else {
        prev->next = next;
        next->prev = prev;
        target_user->next = NULL;
        target_user->prev = NULL;
        removed = true;
    }

    /* Remove file descriptor from read set of list */
    FD_CLR(target_user->socket_des, &(target_list->read_set));

    /* Update the maximum socket descriptor if necessary */
    int new_max = 0;
    for(user *temp = active_user_list->list; temp != NULL; temp = temp->next) {
        if(temp->socket_des > new_max) {
            new_max = temp->socket_des;
        }
    }
    active_user_list->max_descriptor = new_max;

    return removed;
}

pid_t create_chat_window(int client_fd, bool is_new_user, user_list *target_list,
    user *target_user, char *current_username, char *destination_username,
    char *source_username, char *chat_message) {

    pid_t pid; // Counter for Child Process ID
    char *chat_win_args[9] = {"/usr/bin/xterm", "-geometry", "45x35+0+0", "-T",
                               NULL, "-e", "./chat", NULL, NULL};
    int sv[2] = {0};
    char* socket = (char*) calloc(1, 10);

    if(strcmp(destination_username, current_username) == 0) {
        chat_win_args[4] = source_username;
    }
    else {
        chat_win_args[4] = destination_username;
    }

    /* Attempt to create socket pair for client process to communicate
     * with child chat window */
    int ans = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

    if(ans == 0) {
        /* Attempt to fork the process */
        pid = fork();

        /* Forking failed */
        if(pid < 0) {
            fprintf(stderr, "%sOPENING CHAT WINDOW FAILED: %s%s\n",
                ERROR_PRINT_FORMAT, strerror(errno), DEFAULT_PRINT_FORMAT);
            close(sv[0]);
            close(sv[1]);
        }
        /* Forking succeeded -> Attempt to execv() chat program */
        else if(pid == 0) {
            /* Close unused descriptors */
            close(client_fd);
            close(sv[0]);
            sprintf(socket, "%d", sv[1]);
            chat_win_args[7] = socket;
            /* Execute desired program with given arguments */
            if(execv(*chat_win_args, chat_win_args) < 0) {
                /* Print return code and ERRNO if child process fails */
                fprintf(stderr, "%s%s%s\n",ERROR_PRINT_FORMAT, strerror(errno), DEFAULT_PRINT_FORMAT);

                /* Terminate child process after indicating error occurred */
                exit(EXIT_FAILURE);
            }
        }
        /* Forking succeeded -> Store reference to the chat window process */
        else {
            /* Close unused descriptors */
            close(sv[1]);

            if(is_new_user) {
                /* Create user struct to reference chat window */
                user *new_user = NULL;
                if(strcmp(destination_username, current_username) == 0) {
                    new_user = create_user_struct(source_username, sv[0]);
                }
                else {
                    new_user = create_user_struct(destination_username, sv[0]);
                }
                new_user->chat_win_pid = pid;

                /* Add to the user list to the active user list */
                add_user_struct(target_list, new_user);
            }
            /* Otherwise, update the data fields in the existing user struct */
            else {
                /* Close Dead Socket descriptor and remove it from read set */
                close(target_user->socket_des);
                FD_CLR(target_user->socket_des, &(target_list->read_set));

                /* Update the socket descrpitor and add it to the read set */
                target_user->chat_win_pid = pid;
                target_user->socket_des = sv[0];
                FD_SET(target_user->socket_des, &(target_list->read_set));
            }
        }
    }
    else {
        fprintf(stderr, "%sCREATING SOCKETPAIR FAILED: %s%s\n",
            ERROR_PRINT_FORMAT, strerror(errno), DEFAULT_PRINT_FORMAT);
        pid = -1;
    }

    return pid;
}

char* create_protocol_message(char* protocol_verb, char* username, char* receiver, char* error_code, char* message_payload)
{
    char* buffer_client = calloc(1, MESSAGE_SIZE);
    strcat(buffer_client, protocol_verb); // writes verb to buffer
    if( (strcmp(protocol_verb, WOLFIE_PRO) == 0) || (strcmp(protocol_verb, EIFLOW_PRO) == 0)
        || (strcmp(protocol_verb, BYE_PRO) == 0) || (strcmp(protocol_verb, TIME_PRO) == 0)
        || (strcmp(protocol_verb, LISTU_PRO) == 0) || (strcmp(protocol_verb, SSAPWEN_PRO) == 0)
        || (strcmp(protocol_verb, SSAP_PRO) == 0)) {
        // Add nothing
    }
    else if((strcmp(protocol_verb, IAM_PRO) == 0) || (strcmp(protocol_verb, HI_PRO) == 0)
        || (strcmp(protocol_verb, IAMNEW_PRO) == 0) || (strcmp(protocol_verb, HINEW_PRO) == 0)
        || (strcmp(protocol_verb, AUTH_PRO) == 0) || (strcmp(protocol_verb, UOFF_PRO) == 0)) {

        strcat(buffer_client, " ");
        strcat(buffer_client, username);
    }
    else if((strcmp(protocol_verb, MOTD_PRO) == 0) || (strcmp(protocol_verb, EMIT_PRO) == 0)
        || (strcmp(protocol_verb, NEWPASS_PRO) == 0) || (strcmp(protocol_verb, PASS_PRO) == 0)) {

        strcat(buffer_client, " ");
        strcat(buffer_client, message_payload);
    }
    else if(strcmp(protocol_verb, UTSIL_PRO) == 0) {
        /* Initialize needed counters */
        int max_space_counter = MESSAGE_SIZE;
        int current_size_counter = strlen(buffer_client);
        bool multiple_users = false;
        char *username_temp = NULL;
        user *cursor = active_user_list->list;

        /* Use while-loop to build reply message dynamically */
        while(cursor != NULL) {
            /* Get name of current user */
            username_temp = cursor->username;

            /* Expand existing message buffer when needed */
            if(current_size_counter >= (max_space_counter / 2)
                || (max_space_counter - current_size_counter < strlen(username_temp) + 9) ) {
                max_space_counter = max_space_counter * 2;
                buffer_client = realloc(buffer_client, max_space_counter);
                if(buffer_client == NULL) {
                    fprintf(stderr, "failed to realloc buffer_client\n");
                    exit(EXIT_FAILURE);
                }
            }

            /* Append separator between usernames when needed */
            if(multiple_users) {
                strcat(buffer_client, " \r\n");
            }

            /* Append current username to message */
            strcat(buffer_client, " ");
            strcat(buffer_client, username_temp);

            /* After appending first username to message */
            if(!multiple_users) {
                /* Indicate possibility for more users from list */
                multiple_users = true;
                /* Increment counter tracking current message size */
                current_size_counter += strlen(username_temp) + 1;
            }
            /* Increment current message size for multiple usernames otherwise */
            else {
                current_size_counter += strlen(username_temp) + 4;
            }

            /* Increment position along active user list */
            cursor = cursor->next;
        }

        /* Expand buffer if lacking space for message terminator */
        if(max_space_counter - current_size_counter < 5) {
            buffer_client = realloc(buffer_client, max_space_counter + 10);
            if(buffer_client == NULL) {
                fprintf(stderr, "failed to realloc buffer_client\n");
                exit(EXIT_FAILURE);
            }
        }
    }
    else if(strcmp(protocol_verb, ERR_PRO) == 0) {
        strcat(buffer_client, " ");
        strcat(buffer_client, error_code);
        strcat(buffer_client, " ");
        strcat(buffer_client, message_payload);
    }
    else if(strcmp(protocol_verb, MSG_PRO) == 0) {
        strcat(buffer_client, " ");
        strcat(buffer_client, receiver);
        strcat(buffer_client, " ");
        strcat(buffer_client, username);
        strcat(buffer_client, " ");
        strcat(buffer_client, message_payload);
    }
    else {
        /* Invalid protocol verb, clean up and return NULL */
        free(buffer_client);
        return NULL;
    }

    /* All messages must end with 2 message deliminations */
    strcat(buffer_client, " ");
    strcat(buffer_client, CARRIAGE_ENDING); // write \r\n\r\n

    return buffer_client;
}

char* read_protocol_message(int socket_des) {
    char* message_buffer = calloc(1, MESSAGE_SIZE);
    int max_space_counter = MESSAGE_SIZE;
    int current_size_counter = 0;
    int bytes_read = 0;

    if(message_buffer == NULL) {
        fprintf(stderr, "failed to calloc buffer for read start\n");
        exit(EXIT_FAILURE);
    }

    while(strstr(message_buffer, CARRIAGE_ENDING) == NULL) {
        char test_buff[2] = {'\0'};
        if(current_size_counter >= ( max_space_counter / 2 ) ) {
            max_space_counter = max_space_counter * 2;
            message_buffer = realloc(message_buffer, max_space_counter);
            if(message_buffer == NULL) {
                fprintf(stderr, "failed to realloc buffer\n");
                exit(EXIT_FAILURE);
            }
        }
        if(recv(socket_des, test_buff, 1, MSG_PEEK) > 0) {
            bytes_read = read(socket_des, message_buffer, MESSAGE_SIZE);
            current_size_counter = current_size_counter+bytes_read;
        }
        else {
            fprintf(stderr, "%sFATAL READ ERROR, SOCKET DISCONNECTED%s\n",
                ERROR_PRINT_FORMAT, DEFAULT_PRINT_FORMAT);
            exit(EXIT_FAILURE);
        }
   }
   return message_buffer;
}

void print_protocol_message(char *message, bool received) {
    /* Create buffer for printing the protocol message */
    char *message_buffer = calloc(1, strlen(message));
    char *message_tok = NULL;
    char *saveptr_message_token = NULL;

    strncpy(message_buffer, message, strlen(message));
    message_tok = strtok_r(message_buffer, MESSAGE_FIELD_DELIM, &saveptr_message_token);
    if(received) {
        printf("%sRECEIVED VERB: ", VERBOSE_PRINT_FORMAT);
    }
    else {
        printf("%sSENT VERB: ", VERBOSE_PRINT_FORMAT);
    }

    while(message_tok != NULL) {
        if(isspace(*message_tok)) {
            message_tok = message_tok + 1;
        }
        printf("%s", message_tok);
        message_tok = strtok_r(NULL, MESSAGE_FIELD_DELIM, &saveptr_message_token);
    }

    printf("%s\n", DEFAULT_PRINT_FORMAT);

    free(message_buffer);
}

void parse_protocol_message(int client_fd, bool is_server, char *username, char *message, int vFlag, int cFlag) {
    /* Create buffer for parsing messsage from socket descriptor */
    char* message_buffer = calloc(1, strlen(message));
    //char *tok = NULL;
    char *message_tok = NULL;
    //char *saveptr_message = NULL;
    char *saveptr_message_token = NULL;
    char *reply_buffer;

    /* Copy the message into the local memory */
    /*char *ttmpp = */strncpy(message_buffer, message, strlen(message));
    //fprintf(stderr, "%sHERE:%s%s\n", ERROR_PRINT_FORMAT, ttmpp, DEFAULT_PRINT_FORMAT);

    /* Tokenize protocol verb from message */
    //tok = strtok_r(message_buffer, CARRIAGE_ENDING, &saveptr_message);
    message_tok = strtok_r(message_buffer, " ", &saveptr_message_token);

    /* When the protocol verb is the WOLFIE -> client login start */
    if(strcmp(message_tok, WOLFIE_PRO) == 0) {
        /* Server sends the reply message to the client */
        reply_buffer = create_protocol_message(EIFLOW_PRO, NULL, NULL, NULL, NULL);
        write(client_fd, reply_buffer, strlen(reply_buffer));

        if(vFlag > 0) {
            print_protocol_message(reply_buffer, false);
        }

        free(reply_buffer);
    }
    /* When protocol verb is the EIFLOW -> server ack of login start */
    else if(strcmp(message_tok, EIFLOW_PRO) == 0) {
        /* Client sends username to server */
        char* verb = (cFlag == 1) ? IAMNEW_PRO : IAM_PRO;
        reply_buffer = create_protocol_message(verb, username, NULL, NULL, NULL);

        if(vFlag > 0) {
            print_protocol_message(reply_buffer, false);
        }

        write(client_fd, reply_buffer, strlen(reply_buffer));
        free(reply_buffer);
    }
    /* When protocol verb is IAM -> Client user identification */
    else if(strcmp(message_tok, IAM_PRO) == 0) {
        /* Server extracts username from client user ID message */
        message_tok = strtok_r(NULL, " ", &saveptr_message_token);

        /* Server processes user login request */
        if(message_tok != NULL) {
            /* Check that the username is a valid user account  */
            bool is_valid_username = false;
            user *cursor = account_list->list;
            while(cursor != NULL) {
                if(strcmp(cursor->username, message_tok) == 0) {
                    is_valid_username = true;
                    break;
                }
                cursor = cursor->next;
            }

            /* Check that given username is not already in the active user list */
            bool is_logged_in = false;
            cursor = active_user_list->list;
            while(cursor != NULL) {
                if(strcmp(cursor->username, message_tok) == 0) {
                    is_logged_in = true;
                    break;
                }
                cursor = cursor->next;
            }

            /* When username is valid account and not currently logged in */
            if(is_valid_username && !is_logged_in) {
                /* Store client descriptor in account list until end of logon message exchanges */
                user *temp = get_user_with_username(message_tok, account_list);
                temp->socket_des = client_fd;

                /* Prompt user for password for existing account */
                reply_buffer = create_protocol_message(AUTH_PRO, message_tok, NULL, NULL,NULL);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);
            }
            /* Otherwise, indicate error with username */
            else {
                /* Switch error message sent based on account presence */
                char *error_code = (!is_valid_username) ? USER_NOT_AVAILABLE_CODE : USERNAME_TAKEN_CODE;
                char *error_message = (!is_valid_username) ? USER_NOT_AVAILABLE_ERROR_MESSAGE : USERNAME_TAKEN_ERROR_MESSAGE;

                /* Send error message to client */
                reply_buffer = create_protocol_message(ERR_PRO, NULL, NULL, error_code, error_message);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);

                /* Setup code to sleep for 100 milliseconds */
                struct timespec tp;
                tp.tv_sec = 0;
                tp.tv_nsec = 100000000;
                nanosleep(&tp, NULL);

                /* Send termination message to client */
                reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);

                /* Close client descriptor as login failed */
                close(client_fd);
            }
        }
    }
    /* When the protocol verb is the IAMNEW -> client new user account login */
    else if(strcmp(message_tok, IAMNEW_PRO) == 0) {
        /* Server sends the reply message to the client */
        /* this is for checking if the new user is in the struct*/
        /* code has to be added to add a user in*/

        /* Check if requested username exists in the valid accounts list */
        message_tok = strtok_r(NULL, " ", &saveptr_message_token);
        bool is_valid_account = true;
        user *cursor = account_list->list;
        while(cursor != NULL) {
            if(strcmp(cursor->username, message_tok) == 0) {
                is_valid_account = false;
                break;
            }
            cursor = cursor->next;
        }

        /* When the requested username is a valid account */
        if(is_valid_account) {
            /* Create user struct for new active user */
            user *new_user = create_user_struct(message_tok, client_fd);

            /* Add the new user struct to list of valid user accounts */
            add_user_struct(account_list, new_user);

            /* Send reply to client indicating successful login */
            reply_buffer = create_protocol_message(HINEW_PRO, message_tok, NULL, NULL,NULL);
            write(client_fd, reply_buffer, strlen(reply_buffer));

            if(vFlag > 0) {
                print_protocol_message(reply_buffer, false);
            }

            free(reply_buffer);
        }
        else{
            /* Send error message to client */
            char *error_message_buffer = calloc(1, (strlen(USERNAME_TAKEN_ERROR_MESSAGE) + strlen(message_tok)) );
            strcat(error_message_buffer, USERNAME_TAKEN_ERROR_MESSAGE);
            strcat(error_message_buffer, message_tok);

            reply_buffer = create_protocol_message(ERR_PRO, NULL, NULL, USERNAME_TAKEN_CODE, error_message_buffer);
            write(client_fd, reply_buffer, strlen(reply_buffer));

            if(vFlag > 0) {
                print_protocol_message(reply_buffer, false);
            }

            free(error_message_buffer);
            free(reply_buffer);

            /* Send termination message to client */
            reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
            write(client_fd, reply_buffer, strlen(reply_buffer));

            if(vFlag > 0) {
                print_protocol_message(reply_buffer, false);
            }

            free(reply_buffer);

            /* Close client descriptor as login failed */
            close(client_fd);
        }
    }
    /* When protocol verb is HI -> confirmation of successful login by client onto server */
    else if(strcmp(message_tok, HI_PRO) == 0) {
        /* Client extracts username from server login confirm message */
        message_tok = strtok_r(NULL, " ", &saveptr_message_token);

        /* Client prints login confirmation message request */
        if(message_tok != NULL) {
            printf("%sSuccessfully logged in as: %s\n", DEFAULT_PRINT_FORMAT, message_tok);
        }
    }
    /* When protocol verb is HINEW -> confirmation of successful login by client onto server */
    else if(strcmp(message_tok, HINEW_PRO) == 0) {
        /* Client extracts username from server login confirm message */
        message_tok = strtok_r(NULL, " ", &saveptr_message_token);
        printf("%sUsername %s is available for creation.\n", DEFAULT_PRINT_FORMAT, message_tok);

        /* Prompt client for password for new user account */
        char* new_password = getpass("Please enter a password for the new account: ");

        /* Send reply containing password to server */
        reply_buffer = create_protocol_message(NEWPASS_PRO, message_tok, NULL, NULL, new_password);
        write(client_fd, reply_buffer, strlen(reply_buffer));

        if(vFlag > 0) {
            print_protocol_message(reply_buffer, false);
        }

        free(reply_buffer);
    }
    /* When protocol verb is NEWPASS -> check new password to then finish new account creation */
    else if(strcmp(message_tok, NEWPASS_PRO) == 0) {
        /* Retrieve password from protocol message */
        message_tok = strtok_r(NULL, " ", &saveptr_message_token);

        /* When the password meets the required security criteria */
        if(is_password_valid(message_tok)) {
            /* Send message to client indicating valid password */
            reply_buffer = create_protocol_message(SSAPWEN_PRO, message_tok, NULL, NULL,message_tok);
            write(client_fd, reply_buffer, strlen(reply_buffer));

            if(vFlag > 0) {
                print_protocol_message(reply_buffer, false);
            }

            free(reply_buffer);

            /* Get references to the user structs for the new user in both lists */
            user *account_user = get_user_with_fd(client_fd, account_list);
            user *new_user = create_user_struct(account_user->username, client_fd);

            /* Attempt to generate random salt for new user account password */
            unsigned char* salt_buff = calloc(1, 8);
            int ans = RAND_bytes(salt_buff, 8);

            /* If the generation of the salt fails */
            if(ans < 1) {
                free(salt_buff);

                /* Indicate internal error to client */
                reply_buffer = create_protocol_message(ERR_PRO, NULL, NULL, SERVER_ERROR_CODE, SERVER_ERROR_MESSAGE);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);

                /* Setup code to sleep for 100 milliseconds */
                struct timespec tp;
                tp.tv_sec = 0;
                tp.tv_nsec = 100000000;
                nanosleep(&tp, NULL);

                /* Notify client of disconnection due to error */
                reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);

                /* Clean up client data from user lists */
                destroy_user_struct(new_user);
                remove_user_struct(account_user, account_list);
                destroy_user_struct(account_user);

                /* Close client descriptor as login failed */
                close(client_fd);
            }
            /* Otherwise, finish creating the new user account */
            else {
                /* Attempt to create the hash of the password */
                char *hash_input_buffer = calloc(1, (strlen(message_tok) + 8));
                unsigned char *md = calloc(1, 32);
                strcat(hash_input_buffer, message_tok);
                strcat(hash_input_buffer, (char *) salt_buff);
                unsigned char* hash = SHA256((unsigned char *) hash_input_buffer, (strlen(message_tok) + 8), md);

                /* Store the salt and the hashed password into the account struct */
                account_user->hash = hash;
                account_user->salt = salt_buff;

                /* Add the new user struct to list of active users */
                add_user_struct(active_user_list, new_user);

                /* Setup code to sleep for 100 milliseconds */
                struct timespec tp;
                tp.tv_sec = 0;
                tp.tv_nsec = 100000000;
                nanosleep(&tp, NULL);

                /* Indicate to client that login was successful */
                reply_buffer = create_protocol_message(HI_PRO, new_user->username, NULL, NULL,NULL);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(hash_input_buffer);
                free(reply_buffer);
            }
        }
        /* Otherwise, indicate that password was not secure enough */
        else{
            /* Indicate to client that password was invalid */
            reply_buffer = create_protocol_message(ERR_PRO, NULL, NULL, BAD_PASSWORD_CODE, BAD_PASSWORD_ERROR_MESSAGE);
            write(client_fd, reply_buffer, strlen(reply_buffer));

            if(vFlag > 0) {
                print_protocol_message(reply_buffer, false);
            }

            free(reply_buffer);

            /* Setup code to sleep for 500 milliseconds */
            struct timespec tp;
            tp.tv_sec = 0;
            tp.tv_nsec = 100000000;
            nanosleep(&tp, NULL);

            /* Notify client of disconnection */
            reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
            write(client_fd, reply_buffer, strlen(reply_buffer));

            if(vFlag > 0) {
                print_protocol_message(reply_buffer, false);
            }

            free(reply_buffer);

            /* Clean up client data from user lists */
            user *account_user = get_user_with_fd(client_fd, account_list);
            remove_user_struct(account_user, account_list);
            destroy_user_struct(account_user);

            /* Close client descriptor as login failed */
            close(client_fd);
        }
    }
    /* When protocol verb is MOTD -> welcoming message from server */
    else if(strcmp(message_tok, MOTD_PRO) == 0) {
        /* Extract the welcoming message from the protocol message */
        message_tok = strtok_r(NULL, MESSAGE_FIELD_DELIM, &saveptr_message_token);
        message_tok[strlen(message_tok)-1] = '\0';

        /* Print welcoming message to client */
        printf("%s%s\n", DEFAULT_PRINT_FORMAT, message_tok);
    }
    /* When protocol message is TIME -> login time request from server */
    else if(strcmp(message_tok, TIME_PRO) == 0) {
        /* Get reference to user requesting time */
        user *temp = get_user_with_fd(client_fd, active_user_list);

        /* Convert retrieved user login time into integer string */
        char *time_str = calloc(1, 20);
        time_t current_time = time(NULL);
        time_t session_time = difftime(current_time, temp->login_time);
        sprintf(time_str, "%lu", session_time);

        /* Send error message to client */
        reply_buffer = create_protocol_message(EMIT_PRO, NULL, NULL, NULL, time_str);
        write(client_fd, reply_buffer, strlen(reply_buffer));

        if(vFlag > 0) {
            print_protocol_message(reply_buffer, false);
        }

        free(time_str);
        free(reply_buffer);
    }
    /* When protocol verb is EMIT -> session time query response */
    else if(strcmp(message_tok, EMIT_PRO) == 0) {
        /* Extract the time from the message */
        message_tok = strtok_r(NULL, " ", &saveptr_message_token);
        char* end_ptr;
        time_t session_time = (time_t) strtol(message_tok, &end_ptr, 10);

        /* Calculate current sueesion time */
        int hours = session_time / 3600;
        session_time = session_time % 3600;
        int minutes = session_time / 60;
        session_time = session_time % 60;
        int seconds = session_time;

        /* Print current session duration */
        printf("%sconnected for %d hour(s), %d minute(s), and %d second(s)\n",
            DEFAULT_PRINT_FORMAT, hours, minutes, seconds);
    }
    /* When protocol verb is LISTU -> active users query from client */
    else if(strcmp(message_tok, LISTU_PRO) == 0) {
        /* Server sends the reply message to the client */
        reply_buffer = create_protocol_message(UTSIL_PRO, NULL, NULL, NULL, NULL);
        write(client_fd, reply_buffer, strlen(reply_buffer));

        if(vFlag > 0) {
            print_protocol_message(reply_buffer, false);
        }

        free(reply_buffer);
    }
    /*checks to see if the username is present in the list */
    else if(strcmp(message_tok, AUTH_PRO) == 0) {
        /* Client extracts username from server login confirm message */
        message_tok = strtok_r(NULL, " ", &saveptr_message_token);
        printf("%sUsername %s is available for login.\n", DEFAULT_PRINT_FORMAT, message_tok);

        /* Prompt client for password for new user account */
        char* password = getpass("Please enter the password for the account: ");

        /* Send reply containing password to server */
        reply_buffer = create_protocol_message(PASS_PRO, message_tok, NULL, NULL, password);
        write(client_fd, reply_buffer, strlen(reply_buffer));

        if(vFlag > 0) {
            print_protocol_message(reply_buffer, false);
        }

        free(reply_buffer);
    }
    /*prompts the user for a password so we check to see if that is the correct password for the user logging in */
    else if(strcmp(message_tok, PASS_PRO) == 0) {
        /* Retrieve password from protocol message */
        message_tok = strtok_r(NULL, " ", &saveptr_message_token);

        /* Retrieve salt and hash for account to log into */
        user *target_account = get_user_with_fd(client_fd, account_list);
        if(target_account != NULL) {
            /* Attempt to create the hash of the password from protocol message */
            char *hash_input_buffer = calloc(1, (strlen(message_tok) + 8));
            unsigned char *md = calloc(1, 32);
            strcat(hash_input_buffer, message_tok);
            strcat(hash_input_buffer, (char *) target_account->salt);
            unsigned char* hash = SHA256((unsigned char *) hash_input_buffer, (strlen(message_tok) + 8), md);
            free(hash_input_buffer);

            /* Compare the hash of the given password with the stored hash */
            int hash_check = memcmp(target_account->hash, hash, 20);
            if(hash_check == 0) {
                /* Indicate to client that password matched */
                reply_buffer = create_protocol_message(SSAP_PRO, NULL, NULL, NULL, NULL);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);

                /* Create struct for client in active user list */
                user *new_user = create_user_struct(target_account->username, client_fd);
                add_user_struct(active_user_list, new_user);

                /* Clear client descriptor from the account list */
                target_account->socket_des = 0;

                /* Setup code to sleep for 100 milliseconds */
                struct timespec tp;
                tp.tv_sec = 0;
                tp.tv_nsec = 100000000;
                nanosleep(&tp, NULL);

                /* Indicate to client that login succeeded */
                reply_buffer = create_protocol_message(HI_PRO, new_user->username, NULL, NULL, NULL);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);
            }
            else {
                /* Indicate to client that password did not match */
                reply_buffer = create_protocol_message(ERR_PRO, NULL, NULL, BAD_PASSWORD_CODE, BAD_PASSWORD_ERROR_MESSAGE);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);

                /* Setup code to sleep for 100 milliseconds */
                struct timespec tp;
                tp.tv_sec = 0;
                tp.tv_nsec = 100000000;
                nanosleep(&tp, NULL);

                /* Notify client of disconnection due to error */
                reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);

                /* Clear client descriptor from the account list */
                target_account->socket_des = 0;

                /* Close client descriptor as login failed */
                close(client_fd);
            }

            free(md);
        }
        /* Indicate internal error in attempting to log client in */
        else {
            /* Indicate internal error to client */
            reply_buffer = create_protocol_message(ERR_PRO, NULL, NULL, SERVER_ERROR_CODE, SERVER_ERROR_MESSAGE);
            write(client_fd, reply_buffer, strlen(reply_buffer));

            if(vFlag > 0) {
                print_protocol_message(reply_buffer, false);
            }

            free(reply_buffer);

            /* Setup code to sleep for 100 milliseconds */
            struct timespec tp;
            tp.tv_sec = 0;
            tp.tv_nsec = 100000000;
            nanosleep(&tp, NULL);

            /* Notify client of disconnection due to error */
            reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
            write(client_fd, reply_buffer, strlen(reply_buffer));

            if(vFlag > 0) {
                print_protocol_message(reply_buffer, false);
            }

            free(reply_buffer);

            /* Close client descriptor as login failed */
            close(client_fd);
        }
    }
    /*returns from PASS verb*/
    else if(strcmp(message_tok, SSAP_PRO) == 0) {
        printf("Password for account matched sucessfully\n");
    }
    /* When the protocol verb is SSAPWEN -> New account password good confirmation */
    else if(strcmp(message_tok, SSAPWEN_PRO) == 0) {
        printf("New account password meets security criteria.\n");
    }
    /* When protocol verb is UTSIL -> active users query response */
    else if(strcmp(message_tok, UTSIL_PRO) == 0) {
        /* Tokenize remainder of message containing active usernames */
        message_tok = strtok_r(NULL, " ", &saveptr_message_token);
        printf("%s------------------------\n"
                 "|     ACTIVE USERS     |\n"
                 "------------------------\n", DEFAULT_PRINT_FORMAT);

        /* Use while-loop to print all active usernames received from server */
        while(message_tok != NULL) {
            bool at_separator = (strcmp(message_tok, MESSAGE_FIELD_DELIM) == 0) ||
                (strcmp(message_tok, CARRIAGE_ENDING) == 0);

            if(!at_separator) {
                printf("%s| %20s |\n", DEFAULT_PRINT_FORMAT, message_tok);
            }

            message_tok = strtok_r(NULL, " ", &saveptr_message_token);
        }

        printf("%s------------------------\n", DEFAULT_PRINT_FORMAT);
    }
    /* When the protocol verb is MSG -> message between clients */
    else if(strcmp(message_tok, MSG_PRO) == 0) {
        /* Retrieve usernames from the message payload */
        char *destination_username = strtok_r(NULL, " ", &saveptr_message_token);
        char *source_username = strtok_r(NULL, " ", &saveptr_message_token);

        /* Retrieve the client chat message from the message payload */
        char *chat_message = strtok_r(NULL, CARRIAGE_ENDING, &saveptr_message_token);

        /* Get reference to the destination user struct */
        user *temp = NULL;
        if(is_server) {
            temp = get_user_with_username(destination_username, active_user_list);
        }
        else {
            /* Check if the current client is the receiver */
            if(strcmp(destination_username, username) == 0) {
                temp = get_user_with_username(source_username, active_user_list);
            }
            else {
                temp = get_user_with_username(destination_username, active_user_list);
            }
        }

        /* When received by the server */
        if(is_server) {
            /* Forward the message to the destination user when they exist */
            if(temp != NULL) {
                /* Create message to send chat message to destination user */
                reply_buffer = create_protocol_message(MSG_PRO, source_username, destination_username, NULL, chat_message);

                /* Echo the protocol message back to the sender */
                write(client_fd, reply_buffer, strlen(reply_buffer));
                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                /* Send the protocol message to the destination user */
                Write(temp->socket_des, reply_buffer, strlen(reply_buffer));
                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);
            }
            /* Otherwise, reply indicating target user does not exist */
            else {
                reply_buffer = create_protocol_message(ERR_PRO, NULL, NULL, USER_NOT_AVAILABLE_CODE, USER_NOT_AVAILABLE_ERROR_MESSAGE);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);
            }
        }

        /* When received by a client */
        else {
            /* When the other client involved in the conversation has a reference */
            if(temp != NULL) {
                /* Check if the PID of the chat window is running  */
                if(kill(temp->chat_win_pid, 0) == 0) {
                    /* Write the message out to the window */
                    if(strcmp(destination_username, username) == 0) {
                        write(temp->socket_des, ">", 1);
                    }
                    else {
                        write(temp->socket_des, "<", 1);
                    }
                    write(temp->socket_des, chat_message, strlen(chat_message));
                    write(temp->socket_des, "\n", 1);
                }
                else {
                    /* Create new chat window process and store the PID in the
                     * existing struct for the other user */
                    pid_t new_chat_win_pid = create_chat_window(client_fd, false,
                        NULL, temp, username, destination_username, source_username, NULL);

                    if(new_chat_win_pid > 0) {
                        temp->chat_win_pid = new_chat_win_pid;

                        /* Write the message out to the window */
                        if(strcmp(destination_username, username) == 0) {
                            write(temp->socket_des, ">", 1);
                        }
                        else {
                            write(temp->socket_des, "<", 1);
                        }
                        write(temp->socket_des, chat_message, strlen(chat_message));
                        write(temp->socket_des, "\n", 1);
                    }
                    else {
                        fprintf(stderr, "%sCould not respawn chat window to display message.\n"
                            "RECEIVED MESSAGE: %s%s\n",
                            ERROR_PRINT_FORMAT, chat_message, DEFAULT_PRINT_FORMAT);
                    }
                }
            }
            /* Otherwise, create a chat window to communicate with the other cllient */
            else {
                create_chat_window(client_fd, true, active_user_list, NULL,
                    username, destination_username, source_username, chat_message);

                /* Check if the current client is the receiver */
                if(strcmp(destination_username, username) == 0) {
                    temp = get_user_with_username(source_username, active_user_list);
                }
                else {
                    temp = get_user_with_username(destination_username, active_user_list);
                }

                if(temp != NULL) {
                    char *buff = calloc(1, strlen(chat_message) + 2);

                    /* Write the message out to the window */
                    if(strcmp(destination_username, username) == 0) {
                        buff[0] = '>';
                    }
                    else {
                        buff[0] = '<';
                    }
                    strncpy(buff+1, chat_message, strlen(chat_message));
                    strcat(buff, "\n");
                    //printf("%s%s", DEFAULT_PRINT_FORMAT, buff);
                    write(temp->socket_des, buff, strlen(buff));

                }
                else {
                    fprintf(stderr, "%sERROR PRINTING TO CHAT WINDOW!!!%s\n",
                        ERROR_PRINT_FORMAT, DEFAULT_PRINT_FORMAT);
                }
            }
        }
    }
    /* When protocol verb is UOFF -> client logged off of server */
    else if(strcmp(message_tok, UOFF_PRO) == 0) {
        /* Retrieve username of user that left chat server */
        message_tok = strtok_r(NULL, " ", &saveptr_message_token);

        /* Indicate that user left the chat server */
        printf("%sUser %s has exited.\n", DEFAULT_PRINT_FORMAT, message_tok);
        fflush(stdout);

        /* Close chat window for leaving user if there is one */
        user *temp = get_user_with_username(message_tok, active_user_list);
        if(temp != NULL) {
            remove_user_struct(temp, active_user_list);

            /* Send the closing request to the chat windows */
            write(temp->socket_des, "/close\n", 7);

            /* Wait for ack from chat window */
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
                int test = recv(temp->socket_des, chat_buffer, 1, MSG_PEEK);
                if(test > 0) {
                    bytes_read = read(temp->socket_des, chat_buffer, MESSAGE_SIZE);
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

            /* Kill process if ACK not received */
            if(strcmp(chat_buffer, "closeack") != 0) {
                kill(temp->chat_win_pid, 3);
            }

            close(temp->socket_des);
            destroy_user_struct(temp);
        }
    }
    /* When protocol verb is BYE -> connection termination */
    else if(strcmp(message_tok, BYE_PRO) == 0) {
        /* Vary task depending on whether caller is client or server */
        if(is_server) {
            /* Get reference to user logging out */
            user *temp = get_user_with_fd(client_fd, active_user_list);

            if(temp != NULL) {
                /*printf("%sConversation with %s finished.\nConnection closed.\n",
                    DEFAULT_PRINT_FORMAT, temp->username);*/
                /* Retrieve the name of the leaving user */
                char *departing_username = calloc(1, strlen(temp->username));
                strncpy(departing_username, temp->username, strlen(temp->username));

                /* Free up the user name in the list */
                remove_user_struct(temp, active_user_list);
                destroy_user_struct(temp);

                reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);

                /* Close the client descriptor */
                close(client_fd);

                /* Notify other clients of user log off */
                if(active_user_list->list != NULL) {
                    reply_buffer = create_protocol_message(UOFF_PRO, departing_username, NULL, NULL, NULL);
                    for(user *cursor = active_user_list->list; cursor != NULL; cursor = cursor->next) {
                        /* Check that current user's descriptor is still open */
                        //char test_buff[2] = {'\0'};
                        if(is_fd_open(cursor->socket_des) /*&& (recv(cursor->socket_des, test_buff, 1, MSG_PEEK) != 0)*/) {
                            write(cursor->socket_des, reply_buffer, strlen(reply_buffer));
                            if(vFlag > 0) {
                                print_protocol_message(reply_buffer, false);
                            }
                        }
                        else {
                            /* Indicate error */
                            fprintf(stderr, "%sUser %s cannot be reached!!!%s\n",
                                ERROR_PRINT_FORMAT, cursor->username, DEFAULT_PRINT_FORMAT);
                        }
                    }
                    free(reply_buffer);
                }

                free(departing_username);
            }
        }
        else {
            char buff_test[2] = {'\0'};
            int status = recv(client_fd, buff_test, 1, MSG_PEEK);
            if(status > 0) {
                /* Send reply BYE mesage */
                reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
                write(client_fd, reply_buffer, strlen(reply_buffer));

                if(vFlag > 0) {
                    print_protocol_message(reply_buffer, false);
                }

                free(reply_buffer);
            }

            /* Free all active user data */
            destroy_user_list_struct(active_user_list, false);

            /* Close descriptor */
            close(client_fd);

            free(message_buffer);
            free(message);

            exit(EXIT_SUCCESS);
        }

    }
    /* When the protocol verb is ERR -> print error message */
    else if(strcmp(message_tok, ERR_PRO) == 0) {
        /* Extract the error code from the error message */
        message_tok = strtok_r(NULL, " ", &saveptr_message_token);
        int error_code = atoi(message_tok);

        /* Handle the error message based on the code */
        switch(error_code) {
            /* Username taken at server */
            case 0:
                /* Print error message at client */
                message_tok = strtok_r(NULL, "\r\n\r\n", &saveptr_message_token);
                fprintf(stderr, "%sError on server login: %s%s\n", ERROR_PRINT_FORMAT, message_tok,
                    DEFAULT_PRINT_FORMAT);
                break;
            /* User not available error */
            case 1:
                /* Print error message at client  */
                message_tok = strtok_r(NULL, "\r\n\r\n", &saveptr_message_token);
                fprintf(stderr, "%sCannot send message: %s%s\n", ERROR_PRINT_FORMAT, message_tok, DEFAULT_PRINT_FORMAT);
                break;
            /* New account password is not secure enough */
            case 2:
                /* Print error message at client */
                message_tok = strtok_r(NULL, "\r\n\r\n", &saveptr_message_token);
                fprintf(stderr, "%sLogin failed: %s %s\n", ERROR_PRINT_FORMAT, message_tok, DEFAULT_PRINT_FORMAT);
                break;
            /* Internal error occurred at server */
            case 100:
                /* Print error message at client */
                message_tok = strtok_r(NULL, "\r\n\r\n", &saveptr_message_token);
                fprintf(stderr, "%sUnexpected error: %s %s\n", ERROR_PRINT_FORMAT, message_tok, DEFAULT_PRINT_FORMAT);
                free(message_buffer);

                /* Terminate client program */
                char buff_test[2] = {'\0'};
                int status = recv(client_fd, buff_test, 1, MSG_PEEK);
                if(status > 0) {
                    /* Send reply BYE mesage */
                    reply_buffer = create_protocol_message(BYE_PRO, NULL, NULL, NULL, NULL);
                    write(client_fd, reply_buffer, strlen(reply_buffer));

                    if(vFlag > 0) {
                        print_protocol_message(reply_buffer, false);
                    }

                    free(reply_buffer);
                }

                /* Free all active user data */
                destroy_user_list_struct(active_user_list, false);

                /* Close descriptor */
                close(client_fd);

                free(message_buffer);
                free(message);

                exit(EXIT_FAILURE);
            default:
                fprintf(stderr, "%sUndetermined error occurred. Exiting...%s\n", ERROR_PRINT_FORMAT,
                    DEFAULT_PRINT_FORMAT);
                free(message_buffer);
                close(client_fd);
                exit(EXIT_FAILURE);
                break;
        }

    }
    /* Ignore incorrectly formatted messages */
    else {

    }

    free(message_buffer);


}
//int Pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg)
//{
//  int ans=pthread_create(thread, NULL, start_routine, arg);
//  if(ans!=0)
//  {
//    fprintf(stderr, "pthread_create: %s\n", gai_strerror(ans));
//    exit(1);
//  }
//  return ans;
//}
//int Pthread_detach(pthread_t thread)
//{
//  int ans=pthread_detach(thread);
//  if(ans!=0)
//  {
//    fprintf(stderr, "pthread_detach: %s\n", gai_strerror(ans));
//    exit(1);
//  }
//  return ans;
//}
int Close(int fd)
{
  int ans=close(fd);
  if(ans<0)
  {
    fprintf(stderr, "close: %s\n", gai_strerror(ans));
    exit(1);
  }
  return ans;
}
