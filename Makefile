export V?=0

# Default = QEMU
HOST_CROSS_COMPILE ?= ${PWD}/../toolchains/aarch32/bin/arm-linux-gnueabihf-
TA_CROSS_COMPILE ?= ${PWD}/../toolchains/aarch32/bin/arm-linux-gnueabihf-
TEEC_EXPORT ?= ${PWD}/../optee_client/out/export
TA_DEV_KIT_DIR ?= ${PWD}/../optee_os/out/arm/export-ta_arm32
ARMCC ?= arm-linux-gnueabihf-gcc

.PHONY: all
all:

	make -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)" TEEC_EXPORT=$(TEEC_EXPORT) TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR) HIKEY=$(HIKEY)
	make -C ta TRUSTED_APP=y NOWERROR=y CROSS_COMPILE="$(TA_CROSS_COMPILE)" TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)
	make -C capsule_gen/cmd/cgen
	make -C capsule_gen/cmd/cprov
	make -C capsule_server/server

.PHONY: clean
clean:
	make -C host clean
	make -C ta clean TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)
	make -C capsule_gen/cmd/cgen clean
	make -C capsule_gen/cmd/cprov clean
	make -C capsule_server/server clean
	make -C lua clean
