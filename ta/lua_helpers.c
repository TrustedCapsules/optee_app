#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_api_types.h>

#include <capsuleCommon.h>
#include <capsulePolicy.h>

#include "lua_helpers.h"
#include "capsule_lua_api.h"

void lua_start_context( lua_State **L ) {
	*L = luaL_newstate();
	luaL_openlibs( *L );
}

void lua_close_context( lua_State **L ) {
	if( *L != NULL ) lua_close( *L );
	*L = NULL;	
}

TEE_Result lua_load_policy( lua_State *L, const char* policy ) {
	DMSG("\n%s\n",policy);
	int ret = luaL_loadstring( L, policy ) || lua_pcall( L, 0, 0, 0 );
	if( ret != LUA_OK ) {
		printf( "Cannot load lua policy, got error %d\n", ret );
		return TEE_ERROR_POLICY_FAILED;
	}

	return TEE_SUCCESS;
}

void lua_load_enumerations( lua_State *L ) {
	lua_pushinteger( L, POLICY_NIL );
	lua_setglobal( L, "POLICY_NIL" );
	
	lua_pushinteger( L, POLICY_OP_OPEN );
	lua_setglobal( L, "POLICY_OP_OPEN" );
	lua_pushinteger( L, POLICY_OP_CLOSE );
	lua_setglobal( L, "POLICY_OP_CLOSE" );
	
	lua_pushinteger( L, POLICY_ALLOW );
	lua_setglobal( L, "POLICY_ALLOW" );
	lua_pushinteger( L, POLICY_NOT_ALLOW );
	lua_setglobal( L, "POLICY_NOT_ALLOW" );
	lua_pushinteger( L, POLICY_UPDATED );
	lua_setglobal( L, "POLICY_UPDATED" );
	
	lua_pushinteger( L, POLICY_ERROR_UNKNOWN_OP );
	lua_setglobal( L, "POLICY_ERROR_UNKNOWN_OP" );
	lua_pushinteger( L, POLICY_ERROR_LOC_NOT_AVAIL );
	lua_setglobal( L, "POLICY_ERROR_LOC_NOT_AVAIL" );
	lua_pushinteger( L, POLICY_ERROR_TIME_NOT_AVAIL );
	lua_setglobal( L, "POLICY_ERROR_TIME_NOT_AVAIL" );
	lua_pushinteger( L, POLICY_ERROR_SERVER_REPLY );
	lua_setglobal( L, "POLICY_ERROR_SERVER_REPLY" );
	lua_pushinteger( L, POLICY_ERROR_SERVER_BROKEN_PIPE );
	lua_setglobal( L, "POLICY_ERROR_SERVER_BROKEN_PIPE" );
	lua_pushinteger( L, POLICY_ERROR_KEY_NOT_FOUND );
	lua_setglobal( L, "POLICY_ERROR_KEY_NOT_FOUND" );
	lua_pushinteger( L, POLICY_ERROR_ACCESS_DENIED );
	lua_setglobal( L, "POLICY_ERROR_ACCESS_DENIED" );
	lua_pushinteger( L, POLICY_ERROR_DATA_CORRUPTED );
	lua_setglobal( L, "POLICY_ERROR_DATA_CORRUPTED" );
	lua_pushinteger( L, POLICY_ERROR_UPDATE_FAILURE );
	lua_setglobal( L, "POLICY_ERROR_UPDATE_FAILURE" );
	lua_pushinteger( L, POLICY_ERROR_REDACT_FAILURE );
	lua_setglobal( L, "POLICY_ERROR_REDACT_FAILURE" );
	lua_pushinteger( L, POLICY_ERROR_APPEND_BLACKLIST );
	lua_setglobal( L, "POLICY_ERROR_APPEND_BLACKLIST" );
	lua_pushinteger( L, POLICY_ERROR_REMOVE_BLACKLIST );
	lua_setglobal( L, "POLICY_ERROR_REMOVE_BLACKLIST" );

	lua_pushinteger( L, POLICY_SECURE_STORAGE );
	lua_setglobal( L, "POLICY_SECURE_STORAGE" );
	lua_pushinteger( L, POLICY_TRUSTED_APP );
	lua_setglobal( L, "POLICY_TRUSTED_APP" );
	lua_pushinteger( L, POLICY_CAPSULE_META );
	lua_setglobal( L, "POLICY_CAPSULE_META" );
	lua_pushinteger( L, POLICY_REMOTE_SERVER );
	lua_setglobal( L, "POLICY_REMOTE_SERVER" );
	lua_pushinteger( L, POLICY_LOCAL_DEVICE );
	lua_setglobal( L, "POLICY_LOCAL_DEVICE" );
}

int lua_run_policy( lua_State *L, SYSCALL_OP op ) {
	int cur_stack = lua_gettop( L );
	lua_getglobal( L, POLICY_FUNC );
	lua_pushinteger( L, op );
	int ret = lua_pcall( L, 1, 0, 0 );
	if( ret != LUA_OK ) {
		DMSG("Cannot run lua evaluate_policy func, got error %d -", ret);
		printf( "Cannot run lua evaluate_policy func, got error %d -", ret );
		if( lua_isstring( L, -1 ) ) {
			const char* errString = lua_tostring( L, -1 );
			printf( " %s", errString );
			// TODO: Changed strstr to strcmp
			if( strcmp( errString, POLICY_UPDATED_ERROR_MSG ) == 0 ) {
				ret = UPDATED;
			}
			lua_pop( L, 1 );
		}
		//printf("\n");
	}
	lua_settop( L, cur_stack );
	return ret;
}

size_t lua_get_comment( lua_State *L, char* comment, size_t len ) {
	lua_getglobal( L, POLICY_COMMENT );
	if( !lua_isstring( L, -1 ) ) {
		return 0;
	}
	
	size_t commentLength;
	const char* lstrPtr = lua_tolstring( L, -1, &commentLength );
	// truncate comment if comment length is greater than len of provided
    // comment buffer 
	memcpy( comment, lstrPtr, len > commentLength ? commentLength : len );
	lua_pop( L, 1 );
	return len > commentLength ? commentLength : len;
}

RESULT lua_get_policy_result( lua_State *L ) {
	lua_getglobal( L, POLICY_RESULT );
	if( !lua_isinteger( L, -1 ) ) {
		return NOT_ALLOW;
	}
	int result = lua_tointeger( L, -1 );
	lua_pop( L, 1 );
	return result;
}

bool lua_get_log( lua_State *L, SYSCALL_OP op ) {
	lua_getglobal( L, op == OPEN_OP ? POLICY_LOG_OPEN : POLICY_LOG_CLOSE );
	if( !lua_isboolean( L, -1 ) ) {
		return false;
	}
	bool log = lua_toboolean( L, -1 );
	lua_pop( L, 1 );
	return log;
}

size_t lua_get_server( lua_State *L, char* IP, int len, int* port ) {
	lua_getglobal( L, POLICY_SERVER );
	if( !lua_isstring( L, -1 ) ) {
		return 0;
	}

	size_t 		IPPortLength;
	const char* lstrPtr = lua_tolstring( L, -1, &IPPortLength );

	const char* colon = strchr( lstrPtr, ':' );
	if ( colon != NULL && colon - lstrPtr <= len ) {
		memcpy( IP, lstrPtr, colon - lstrPtr );
		*port = atoi(++colon);
		IPPortLength = colon - lstrPtr;
	} else {
		IPPortLength = 0;
	}
	lua_pop( L, 1 );
	return IPPortLength;
}

int lua_get_policy_version( lua_State *L ) {
	lua_getglobal( L, POLICY_VERSION );
	if( !lua_isinteger( L, -1 ) ) {
		return 0;
	}
	int result = lua_tointeger( L, -1 );
	lua_pop( L, 1 );
	return result;
}

size_t lua_get_string( lua_State *L, char* varName, char* str, size_t len ) {
	lua_getglobal( L, varName );
	if( !lua_isstring( L, -1 ) ) {
		return 0;
	}
	
	size_t strLen;
	const char* lstrPtr = lua_tolstring( L, -1, &strLen );
	if( strLen < len ) {
		memcpy( str, lstrPtr, strLen );
	}
	lua_pop( L, 1 );
	return strLen < len ? strLen : 0;
}
