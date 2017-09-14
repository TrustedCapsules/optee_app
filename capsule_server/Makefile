SERVER = capsule_server
PORT ?= 3490
LIBS = -ltomcrypt -ltfm 
CC = gcc
CFLAGS = -Wall -DTFM_DESC -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -I../common -I../capsule_gen/src/ -I../protobuf_common

ifdef DEBUG
	CFLAGS += -g -DDEBUG
else 
	CFLAGS += -O3
endif

LIBTOMCRYPT_SRC_DIR = ../capsule_gen/src
PROTOBUF_COMMON_DIR = ../protobuf_common/server_out

.PHONY: default all clean

default: $(SERVER)
all: default

OBJECTS_TARGET = capsule_process.o echo_process.o main.o server_op.o
OBJECTS_EXTERNAL = $(LIBTOMCRYPT_SRC_DIR)/capsule_util.o   	 \
				   $(PROTOBUF_COMMON_DIR)/amessage.pb-c.o 	 \
				   $(PROTOBUF_COMMON_DIR)/protobuf-c.o    	 \
				   $(PROTOBUF_COMMON_DIR)/serialize_common.o 
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER): $(OBJECTS_TARGET) $(OBJECTS_EXTERNAL)
	$(CC) $(CFLAGS) $(OBJECTS_TARGET) $(OBJECTS_EXTERNAL)  	\
	      -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(SERVER) 

server-test-simple:
	./capsule_server $(PORT) ECHO_SIMPLE
server-test-enc-ser:
	./capsule_server $(PORT) ECHO_ENC_SER
server-test-capsule:
	./capsule_server $(PORT) CAPSULE
