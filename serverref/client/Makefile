SERVER = capsule_client
LIBS = -ltomcrypt -ltfm -lpthread 
CC = gcc
COMMON = ../../commonref
CFLAGS = -Wall -DTFM_DESC -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable \
		 -I$(COMMON)

ifdef DEBUG
	CFLAGS += -g -DDEBUG
else 
	CFLAGS += -O3
endif

.PHONY: default all clean

default: $(SERVER)
all: default

OBJECTS_TARGET = main.o client_helper.o ../common/serverTomCrypt.o
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
