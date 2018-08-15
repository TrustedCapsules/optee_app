CC		= $(CROSS_COMPILE)gcc
LD		= $(CROSS_COMPILE)ld
AR		= $(CROSS_COMPILE)ar
NM		= $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

INCLUDE_WARN=""

CFG_TEE_TA_LOG_LEVEL ?= 2
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) -DTRUSTED_APP \
		   	-DTRUSTED_APP_BUILD -DLUA_COMPAT_MATHLIB -I../common -I../lua -I$(PROTOBUF_SRC_DIR)

ifeq ($(CFG_TA_GPROF_SUPPORT),y)
CPPFLAGS += -pg
#CFLAGS_ta_arm64=-pg
#CFLAGS_ta_arm32=-pg
endif

ifdef HIKEY
CPPFLAGS += -DHIKEY
endif


BINARY=ffa39702-9ce0-47e0-a1cb-4048cfdb847d

#TA_DEV_KIT_MK:=$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

#ifneq ($(strip $(wildcard $TA_DEV_KIT_MK)),)
include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
#else
#INCLUDE_WARN="\n\n\nWARNING: TA make could not find ${TA_DEV_KIT_MK}\n\n\n"
#endif

#.PHONY: pre-build
#pre-build:
#include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

.PHONY: all
all: $(BINARY).ta

.PHONY: clean
clean:
	rm -f $(BINARY).ta
	rm -f $(BINARY).dmp
	rm -f *.elf
	rm -f *.o
	rm -f *.map
	rm -f *.lds	
	rm -f .*.o.d
	rm -f .*.o.cmd
	rm -f .*.ld.d
	rm -rf home/
