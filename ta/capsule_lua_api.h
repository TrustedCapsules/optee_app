#ifndef CAPSULE_LUA_API_H
#define CAPSULE_LUA_API_H

// TEE<->Lua API
RESULT 		TEE_getLocation( int* longitude, int* latitude, const WHERE w );
RESULT 		TEE_getTime(lua_State *L, uint32_t *ts, const WHERE w);
RESULT 		TEE_getState(lua_State *L, const char *key, size_t keyLen,
					char *value, size_t *valueLen, const WHERE w);
RESULT 		TEE_setState(lua_State *L,const char *key, size_t keyLen,
					const char *value, size_t valueLen, const WHERE w);
RESULT 		TEE_deleteCapsule(void);
int 		TEE_capsuleLength( CAPSULE c );
RESULT 		TEE_appendToBlacklist( const char* str, size_t strLen, const WHERE w );
RESULT 		TEE_removeFromBlacklist( const char* str, size_t strLen, const WHERE w );
RESULT 		TEE_redact( const size_t start, const size_t end, 
				  	    const char* replaceStr, size_t len );
RESULT 		TEE_updatePolicy( lua_State *L );
int 		TEE_readCapsuleData( char** buf, size_t len, size_t offset, CAPSULE c );
RESULT 		lua_get_server_ip_port(lua_State *L, char *ts, int *port);
SYSCALL_OP TEE_get_op(void);

#endif
