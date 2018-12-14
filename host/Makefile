CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

OBJS = err_ta.o \
	   key_data.o \
	   capsule_command.o \
	   capsule_test.o
	    
OBJS_SINGLE = 	err_ta.o \
	   			key_data.o \
	   			capsule_command.o \
	   			single_op.o

# capsule_benchmark.o \
	   
OBJS_Network = err_ta.o \
	   		   key_data.o \
	   		   capsule_command.o \
	   		   capsule_test_network.o

OBJS_Policy = err_ta.o \
			  key_data.o \
			  capsule_command.o \
			  capsule_test_policy.o

OBJS_Breakdown = err_ta.o \
				 key_data.o \
				 capsule_command.o \
				 capsule_breakdown.o

CFLAGS += -Wall -g -O0 -I../common -I$(TEEC_EXPORT)/include -I$(TA_DEV_KIT_DIR)/host_include

ifdef HIKEY
CFLAGS += -DHIKEY=y
endif


LDADD += -lteec -lm -L$(TEEC_EXPORT)/lib 

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: all
all: single_op capsule_test

#capsule_test_network capsule_test_policy capsule_breakdown

capsule_test: $(OBJS)
	$(CC) $(OBJS) $(LDADD) -o $@

single_op: $(OBJS_SINGLE)
	$(CC) $(OBJS_SINGLE) $(LDADD) -o $@  
	
capsule_test_network: $(OBJS_Network)
	$(CC) $(OBJS_Network) $(LDADD) -o $@  

capsule_test_policy: $(OBJS_Policy)
	$(CC) $(OBJS_Policy) $(LDADD) -o $@

capsule_breakdown: $(OBJS_Breakdown)
	$(CC) $(OBJS_Breakdown) $(LDADD) -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) capsule_test
	rm -f $(OBJS_SINGLE) single_op 
	rm -f $(OBJS_Network) capsule_test_network
	rm -f $(OBJS_Policy) capsule_test_policy
	rm -f $(OBJS_Breakdown) capsule_test_breakdown

