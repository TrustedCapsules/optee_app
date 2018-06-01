TARGET = cgen
LIBS = -ltomcrypt -ltfm 
CC = gcc

COMMON = ../../../commonref

CFLAGS = -Wall -DTFM_DESC -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable \
		-I$(COMMON)

ifdef DEBUG
	CFLAGS += -g -DDEBUG
else 
	CFLAGS += -O3
endif

.PHONY: default all clean

default: $(TARGET) 

all: default

OBJECTS_TARGET = main.o gen_helper.o $(COMMON)/capsuleCrypt.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS_TARGET)
	$(CC) $(OBJECTS_TARGET) -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
	-rm -f $(COMMON)/*.o 
