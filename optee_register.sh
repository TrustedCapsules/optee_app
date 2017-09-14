#!/bin/sh

#Register AES keys into TEE and start the interceptor
tee-supplicant &

sleep 1

capsule_test REGISTER_KEYS
modprobe interceptor
