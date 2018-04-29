#ifndef LUA_HELPER_H
#define LUA_HELPER_H

void lua_start_context( lua_State **L );
void lua_close_context( lua_State **L );
void lua_load_policy( lua_State *L, const char* policy );
int	 lua_run_policy( lua_State *L, SYSCALL_OP op );
void lua_load_enumerations( lua_State *L );

size_t 		lua_get_comment( lua_State *L, char* comment, int len );
RESULT 		lua_get_policy_result( lua_State *L );
bool   		lua_get_log( lua_State *L, SYSCALL_OP op );
size_t 		lua_get_server( lua_State *L, char* IP, int len, int* port );
int    		lua_get_policy_version( lua_State *L );
size_t 		lua_get_string( lua_State *L, char* varName, char* str, size_t len );

#endif

