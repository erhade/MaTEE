OBJS:=flush_cache
CC=aarch64-linux-gnu-gcc
CFLAGS += -Wall

all: $(OBJS)

flush_cache: flush_cache.c
	$(CC) $^ -o $@ $(CFLAGS) 

clean:
	rm -f $(OBJS)
