CC = gcc
CFLAGS = -Wall -DSERVER -Wno-unused-variable -Wno-unused-function \
 		 -Wno-unused-but-set-variable -I../common -I../capsule_gen/src/ \
		 -I../capsule_server -I../ta 
#-I../../optee_os/out/arm/export-ta_arm32/include # this removes the include issue but causes compile errors

OBJECTS_TARGET = amessage.pb-c.o protobuf-c.o serialize_common.o

ifdef DEBUG
	CFLAGS += -g -DDEBUG
else 
	CFLAGS += -O3
endif

ifdef TRUSTEDAPP
	OBJDIR_SERVER = .
else
 	OBJDIR_SERVER = server_out
endif

.PHONY: default all clean

all: default
default: server 
server: directories_server $(OBJECTS_TARGET)


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $(OBJDIR_SERVER)/$@

directories_server:
	mkdir -p $(OBJDIR_SERVER)

protobuf:
	protoc-c --c_out=. amessage.proto

clean:
	-rm -rf $(OBJDIR_SERVER)
	-rm -f *.o	
