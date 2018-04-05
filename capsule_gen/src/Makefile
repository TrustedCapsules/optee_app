TARGET = capsule_gen
LIBS = -ltomcrypt -ltfm 
CC = gcc
CFLAGS = -Wall -DTFM_DESC -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -I../../common 

ifdef DEBUG
	CFLAGS += -g -DDEBUG
else 
	CFLAGS += -O3
endif

.PHONY: default all clean

default: $(TARGET) 
all: default

OBJECTS_TARGET = capsule_util.o capsule_gen.o 

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS_TARGET)
	$(CC) $(OBJECTS_TARGET) -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET) 

encode-capsule:
	mkdir -p ../capsules/sample_capsules
	./$(TARGET) encode -n $(NAME) -d ../data/$(NAME).data -p ../data/$(NAME).policy -k ../data/default.kvstore -o ../capsules/sample_capsules

decode-capsule:
	./$(TARGET) decode -n $(NAME)
