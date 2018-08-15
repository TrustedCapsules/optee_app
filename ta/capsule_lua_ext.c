#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <luaconf.h>
#include <lauxlib.h>

#include <capsuleCommon.h>
#include <capsulePolicy.h>

#include "capsule_lua_api.h"
#include "capsule_lua_ext.h"
#include "lua_helpers.h"

static int luaE_getState( lua_State *L ) {
	const char* key = luaL_checkstring( L, -2 );
	const int   where = luaL_checkinteger( L, -1 );
	
	char 		value[ POLICY_STATE_MAX_VALUE_SIZE ] = {0};
	size_t 		len = 0;
	DMSG("\n\nhere\n\n");
	RESULT res = TEE_getState( key, strlen(key), value, &len, where );
	DMSG("\n\nhere here\n\n");
	lua_pushlstring( L, (const char*) value, len ); 
	lua_pushinteger( L, res );
	return 2;
}

static int luaE_setState( lua_State *L ) {
	const char* key = luaL_checkstring( L, -3 );
	const char* value = luaL_checkstring( L, -2 );
	const int   where = luaL_checkinteger( L, -1 );

	RESULT res = TEE_setState( key, strlen(key), value, strlen(value), where );

	lua_pushinteger( L, res );
	return 1;
}

static int luaE_getLocation( lua_State *L ) {
	const int where = luaL_checkinteger( L, -1 );	
	
	int longitude, latitude;
	RESULT res = TEE_getLocation( &longitude, &latitude, where );
	
	lua_pushinteger( L, longitude );
	lua_pushinteger( L, latitude );
	lua_pushinteger( L, res );	

	return 3;
}

static int luaE_getTime( lua_State *L ) {
	const int where = luaL_checkinteger( L, -1 );	
	
	uint32_t ts;
	RESULT res = TEE_getTime( &ts, where );
	
	lua_pushinteger( L, ts );
	lua_pushinteger( L, res );	

    return 2;	
}

static int luaE_readOriginalCapsuleData( lua_State *L ) {
	const int	offset = luaL_checkinteger( L, -2 );
	const int 	len	   = luaL_checkinteger( L, -1 );
	
	char	*buf = NULL; 
	int num = TEE_readCapsuleData( &buf, 
				len < POLICY_READ_MAX_SIZE ? len : POLICY_READ_MAX_SIZE, 
				offset, ORIGINAL );

	if ( num < 0 ) {
		lua_pushlstring( L, NULL, 0 );
	} else {
		lua_pushlstring( L, (const char*) buf, num );
	}
	lua_pushinteger( L, num );
	return 2;	
}

static int luaE_originalCapsuleLength( lua_State *L ) {
	lua_pushinteger( L, TEE_capsuleLength( ORIGINAL ) );
	return 1;
}

static int luaE_deleteCapsule( lua_State *L ) {
	UNUSED( L );
	TEE_deleteCapsule();
	/* Code should never reach here */
	return 0;
}

static int luaE_updatePolicy( lua_State *L ) {
	RESULT res = TEE_updatePolicy( L );
	if ( res == UPDATED ) luaL_error( L, "policy updated" );
	lua_pushinteger( L, res );
	return 1;
}

static int luaE_redact( lua_State *L ) {
	const int 	start 	   = luaL_checkinteger( L, -3 );
	const int 	end   	   = luaL_checkinteger( L, -2 );
	const char* replaceVar = luaL_checkstring( L, -1 ); 

	//-----------Fill-in here--------------
	// Suggested design: op should be a state in optee app. We cannot fetch this
	// from Lua as it exists there only as a local state.
	//TODO: FIX THIS.
	SYSCALL_OP op = TEE_get_op();
	//-------------------------------------
	if( op != OPEN_OP ) {
		lua_pushinteger( L, POLICY_ERROR_REDACT_FAILURE );
		return 1;
	}

	RESULT res = TEE_redact( start, end, replaceVar, strlen( replaceVar ) );
	lua_pushinteger( L, res ); 
	return 1;
}

static int luaE_readNewCapsuleData( lua_State *L ) {
	const int	offset = luaL_checkinteger( L, -2 );
	const int 	len	   = luaL_checkinteger( L, -1 );

	//-----------Fill-in here--------------
	// Suggested design: op should be a state in optee app. We cannot fetch this
	// from Lua as it exists there only as a local state.
	SYSCALL_OP op = TEE_get_op();
	//-------------------------------------
	if( op != CLOSE_OP ) {
		lua_pushlstring( L, NULL, 0 );
		lua_pushinteger( L, -1 );
		return 2;
	}
	
	char	*buf = NULL; 
	int 	num = TEE_readCapsuleData( &buf, 
				len < POLICY_READ_MAX_SIZE ? len : POLICY_READ_MAX_SIZE, 
				offset, NEW );

	if ( num < 0 ) {
		lua_pushlstring( L, NULL, 0 );
	} else {
		lua_pushlstring( L, (const char*) buf, num );
	}
	lua_pushinteger( L, num );
	return 2;	
}

static int luaE_newCapsuleLength( lua_State *L ) {
	//-----------Fill-in here--------------
	// Suggested design: op should be a state in optee app. We cannot fetch this
	// from Lua as it exists there only as a local state.
	SYSCALL_OP op = TEE_get_op();
	//-------------------------------------
	if( op != CLOSE_OP ) {
		lua_pushinteger( L, -1 );
		return 1;
	}
	lua_pushinteger( L, TEE_capsuleLength( NEW ) );
	return 1;
}

static int luaE_appendToBlacklist( lua_State *L ) {
	const char* key   = luaL_checkstring( L, -2 );
	const int   where = luaL_checkinteger( L, -1 );

	RESULT res = TEE_appendToBlacklist( key, strlen(key), where );
	lua_pushinteger( L, res );
	return 1;
}

static int luaE_removeFromBlacklist( lua_State *L ) {
	const char* key   = luaL_checkstring( L, -2 );
	const int   where = luaL_checkinteger( L, -1 );

	RESULT res = TEE_removeFromBlacklist( key, strlen(key), where );
	lua_pushinteger( L, res );
	return 1;
}

static const luaL_Reg ext_funcs[] = {
	/* policy shared */
	{ "getState", 	  				luaE_getState },
	{ "setState", 	  				luaE_setState },
	{ "getLocation",				luaE_getLocation   },
	{ "getTime", 					luaE_getTime },
	{ "readOriginalCapsuleData", 	luaE_readOriginalCapsuleData },
	{ "originalCapsuleLength",		luaE_originalCapsuleLength },
	{ "deleteCapsule",				luaE_deleteCapsule },
	{ "updatePolicy",				luaE_updatePolicy },
	{ "appendToBlacklist",          luaE_appendToBlacklist },
	{ "removeFromBlacklist", 		luaE_removeFromBlacklist },
	
	/* policy open-only */
	{ "redact",						luaE_redact },	

	/* policy close-only */	
	{ "readNewCapsuleData", 		luaE_readNewCapsuleData },
	{ "newCapsuleLength",			luaE_newCapsuleLength },
	
	{ NULL, NULL }
};

TEE_Result lua_add_ext( lua_State *L ) {
	const luaL_Reg *lib;
	for( lib = ext_funcs; lib->func; lib++ ) {
		lua_pushcfunction( L, lib->func );
		lua_setglobal( L, lib->name );
	}
	return TEE_SUCCESS;
}
