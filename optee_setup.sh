#!/bin/sh

#script for testing test_app in QEMU 32-bit

ifconfig lo 127.0.0.1
ifconfig eth0 10.0.0.2
route add default gw 10.0.0.1

modprobe optee_armtz


