OBJS:=server client
CC=aarch64-linux-gnu-gcc
CFLAGS += -O2 -I ./ -Wall
LDLIBS += -pthread -L ./ -lteec

all: $(OBJS)

server: server.c
	$(CC) $^ -o $@ $(CFLAGS) $(LDLIBS)

client: client.c
	$(CC) $^ -o $@ $(CFLAGS) $(LDLIBS)

clean:
	rm -f $(OBJS)
