#ifndef CAPSULE_LUA_EXT_H
#define CAPSULE_LUA_EXT_H

#define SERVER_IP 		"trusted_server"
#define SERVER_PORT 	"port"
#define IPV4_SIZE   	16
#define REPLACE_CHAR    "replace_char"
#define REDACT_OFFSETS  "redact"

TEE_Result add_lua_ext( lua_State *L );

#endif
