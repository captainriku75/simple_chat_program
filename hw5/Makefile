CC = gcc
CFLAGS = -Wall -Werror -g

all: server client chat
server: server.c wrap.c
	$(CC) $(CFLAGS) $^ -o $@ -pthread -lssl -lcrypto
client: client.c wrap.c
	$(CC) $(CFLAGS) $^ -o $@ -pthread -lssl -lcrypto
chat: chat.c
	$(CC) $(CFLAGS) $^ -o $@
clean:
	rm -f *~ *.o server client chat
