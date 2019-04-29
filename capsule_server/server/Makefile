SERVER = capsule_server
LIBS = -ltomcrypt -ltfm -lpthread $(shell python3-config --libs) #includes the "-l" bits
COMMON = ../../common
PYTHON_INCL = $(shell python3-config --includes) 		#includes the "-I" bits

CC = gcc
CFLAGS = -Wall -DTFM_DESC -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable \
		 -I$(COMMON) $(PYTHON_INCL)

ifdef DEBUG
	CFLAGS += -g -DDEBUG
else 
	CFLAGS += -O3
endif

.PHONY: default all clean

default: $(SERVER)
all: default

OBJECTS_TARGET = main.o server_helper.o server_op.o hash.o linkedlist.o ../common/serverTomCrypt.o
OBJECTS_EXTERNAL = $(COMMON)/capsuleCrypt.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER): $(OBJECTS_TARGET) $(OBJECTS_EXTERNAL)
	$(CC) $(CFLAGS) $(OBJECTS_TARGET) $(OBJECTS_EXTERNAL) \
	      -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(SERVER)
	-rm -f ../common/*.o 
