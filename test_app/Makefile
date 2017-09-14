#default is QEMU
ARMCC ?= arm-linux-gnueabihf-gcc 

CFLAGS = -Wall -Wno-unused-but-set-variable -Wno-unused-variable 

ifdef HIKEY
CFLAGS += -DHIKEY=${HIKEY}
endif

ifdef DEBUG
	CFLAGS += -g
else
	CFLAGS += -O3 
endif

TARGET = test_app

OBJECTS = test_app.o test_bio.o test_short_story.o test_helper.o test_benchmark.o test_performance.o

all: default 

%.o: %.c
	$(ARMCC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS) 
	$(ARMCC) $(OBJECTS) $(CFLAGS) -o $@

default: $(TARGET) 

clean: 
	-rm -f $(TARGET)
	-rm -f *.o

