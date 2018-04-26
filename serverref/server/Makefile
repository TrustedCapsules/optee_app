SERVER = capsule_server
PORT ?= 3490
LIBS = -ltomcrypt -ltfm -lpthread 
CC = gcc
CFLAGS = -Wall -DTFM_DESC -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -I../../capsule_gen/src/

ifdef DEBUG
	CFLAGS += -g -DDEBUG
else 
	CFLAGS += -O3
endif

LIBTOMCRYPT_SRC_DIR = ../capsule_gen/src

.PHONY: default all clean

default: $(SERVER)
all: default

OBJECTS_TARGET = main.o server_helper.o hash.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER): $(OBJECTS_TARGET)
	$(CC) $(CFLAGS) $(OBJECTS_TARGET) \
	      -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(SERVER) 

server-test-capsule:
	./capsule_server $(PORT)
