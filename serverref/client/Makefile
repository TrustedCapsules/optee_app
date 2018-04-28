SERVER = capsule_client
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

OBJECTS_TARGET = main.o client_helper.o
OBJECTS_EXTERNAL = $(LIBTOMCRYPT_SRC_DIR)/capsule_util.o ../server/server_helper.o ../server/linkedlist.o ../server/hash.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER): $(OBJECTS_TARGET) $(OBJECTS_EXTERNAL)
	$(CC) $(CFLAGS) $(OBJECTS_TARGET) $(OBJECTS_EXTERNAL) \
	      -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(SERVER) 
