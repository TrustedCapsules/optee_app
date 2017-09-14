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
	./$(TARGET) encode $(NAME) ../data/$(NAME).data ../data/$(NAME).policy ../capsules/$(NAME).capsule ../capsules/$(NAME).plt ../capsules/$(NAME).data ../capsules/$(NAME).policy

decode-capsule:
	./$(TARGET) decode $(NAME) ../data/$(NAME).data ../data/$(NAME).policy ../capsules/$(NAME).capsule ../capsules/$(NAME).plt ../capsules/$(NAME).data ../capsules/$(NAME).policy
