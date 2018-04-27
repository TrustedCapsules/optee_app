SERVER = capsule_server
PORT ?= 3490
LIBS = -ltomcrypt -ltfm -lpthread 
LIBTOMCRYPT_SRC_DIR = ../../capsule_gen/src
CC = gcc
CFLAGS = -Wall -DTFM_DESC -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -I$(LIBTOMCRYPT_SRC_DIR) -I../../common

ifdef DEBUG
	CFLAGS += -g -DDEBUG
else 
	CFLAGS += -O3
endif

.PHONY: default all clean

default: $(SERVER)
all: default

OBJECTS_TARGET = main.o server_helper.o server_op.o hash.o linkedlist.o
OBJECTS_EXTERNAL = $(LIBTOMCRYPT_SRC_DIR)/capsule_util.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER): $(OBJECTS_TARGET) $(OBJECTS_EXTERNAL)
	$(CC) $(CFLAGS) $(OBJECTS_TARGET) $(OBJECTS_EXTERNAL) \
	      -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(SERVER) 

server-test-capsule:
	./capsule_server $(PORT)
