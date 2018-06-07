TARGET = cprov
CC = gcc

COMMON = ../../../common

CFLAGS = -Wall -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable \
		-I$(COMMON)

ifdef DEBUG
	CFLAGS += -g -DDEBUG
else 
	CFLAGS += -O3
endif

.PHONY: default all clean

default: $(TARGET) 

all: default

OBJECTS_TARGET = main.o register_capsule.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS_TARGET)
	$(CC) $(OBJECTS_TARGET) -Wall -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
