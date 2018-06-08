TARGET = cprov
CROSS_COMPILE = ../../../../toolchains/aarch64/bin/aarch64-linux-gnu-
CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

OPTEE_APP = ../../..
TEEC = ../../../../optee_client/out/export
TA_DEV_KIT = ../../../../optee_os/out/arm/export-ta_arm32/host_include

CFLAGS += -Wall -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable \
		-I$(OPTEE_APP)/common -I$(OPTEE_APP)/host -I$(TEEC)/include -I$(TA_DEV_KIT)

LDADD += -lteec -lm -L$(TEEC)/lib

ifdef DEBUG
	CFLAGS += -g -DDEBUG
else 
	CFLAGS += -O3
endif

.PHONY: default all clean

default: $(TARGET) 

all: default

OBJECTS_TARGET = main.o register_capsule.o key_data.o err_ta.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ 

$(TARGET): $(OBJECTS_TARGET)
	$(CC) $(OBJECTS_TARGET) -Wall -o $@ $(LDADD)

clean:
	-rm -f *.o
	-rm -f $(TARGET)
