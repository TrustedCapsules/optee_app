export V?=0

# Default = QEMU
HOST_CROSS_COMPILE ?= ${PWD}/../toolchains/aarch32/bin/arm-linux-gnueabihf-
TA_CROSS_COMPILE ?= ${PWD}/../toolchains/aarch32/bin/arm-linux-gnueabihf-
TEEC_EXPORT ?= ${PWD}/../optee_client/out/export
TA_DEV_KIT_DIR ?= ${PWD}/../optee_os/out/arm/export-ta_arm32
ARMCC ?= arm-linux-gnueabihf-gcc
PROTOBUF_SRC_DIR ?= ${PWD}/../optee_app/protobuf_common

.PHONY: all
all:

	make -C protobuf_common server
	make -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)" TEEC_EXPORT=$(TEEC_EXPORT) TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR) HIKEY=$(HIKEY)
	make -C ta TRUSTED_APP=y NOWERROR=y PROTOBUF_SRC_DIR=$(PROTOBUF_SRC_DIR) CROSS_COMPILE="$(TA_CROSS_COMPILE)" TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)
	make -C capsule_gen/src
	make -C capsule_server
	make -C test_app ARMCC=$(ARMCC) TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR) TEEC_EXPORT=$(TEEC_EXPORT)

.PHONY: clean
clean:
	make -C host clean
	make -C ta clean TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)
	make -C capsule_gen/src clean
	make -C capsule_server clean
	make -C test_app clean
	make -C protobuf_common clean
	make -C lua clean
