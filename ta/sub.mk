global-incdirs-y += ../common
srcs-y += capsule_ta.c
srcs-y += capsule_commands.c
srcs-y += capsule_op.c
srcs-y += capsule_helper.c
srcs-y += capsule_lua_ext.c
srcs-y += $(wildcard ../lua/*.c)
srcs-y += $(wildcard $(PWD)/protobuf_common/*.c)
# This used to work with ../protobuf_common/*.c but it looks in the wrong directory for stdio.h
