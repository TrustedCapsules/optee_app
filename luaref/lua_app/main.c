#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#define POLICY_MAX_SIZE 2048

static int getfield( lua_State *L, int key, int tindex ) {
	int result;
	lua_geti(L, tindex, key); /* Pops key, puts t[key] */
	if( !lua_isinteger(L,-1) )
		luaL_error( L, "Redact array must be integers" );
	result = lua_tointeger( L, -1);
	lua_pop( L, 1 ); /* Remove number */
	return result;
}

static void setfield( lua_State *L, int key, int value, int tindex ) {
	lua_pushinteger( L, value );
	lua_seti( L, tindex, key );
}

static int redact_offset( lua_State *L ) {
	const char*  redact_array = luaL_checkstring(L, -1);
	unsigned int i,j,k;
	int          rstart,rend,ustart,uend,rtable,utable;

	lua_getglobal( L, "unredacted" );
	if( !lua_istable( L, -1 ) )
		luaL_error( L, "Expecting an array" );

	utable = lua_gettop(L);

	lua_getglobal( L, redact_array );
	if( !lua_istable( L, -1 ) )
		luaL_error( L, "Expecting an array" );

	rtable = lua_gettop(L);

	for( i = 1; i <= lua_rawlen(L, rtable); i=i+2 ) {
		rstart = getfield( L, i, rtable );
	  	rend = getfield( L, i+1, rtable );	
		for( j = 1; j <= lua_rawlen(L, utable) ; j=j+2 ) {
			ustart = getfield( L, j, utable );
			uend = getfield( L, j+1, utable );

			if( rstart <= ustart && rend >= uend ) {
				for( k = j; k <= lua_rawlen(L, utable) - 2; k++ ) {
					lua_geti(L, utable, k+2);
					lua_seti(L, utable, k);
				}		
				lua_pushnil(L);
				lua_seti(L, utable, k);
				lua_pushnil(L);
				lua_seti(L, utable, k+1);	
			} else if( rstart <= ustart && rend < uend && rend >= ustart ) {
				setfield( L, j, rend + 1, utable );
			} else if( rstart > ustart && rend >= uend && rstart <= uend ) {
				setfield( L, j+1, rstart - 1, utable );
			} else if( rstart > ustart && rend < uend ) {
				for( k = lua_rawlen(L, utable) + 2; k > j + 2; k-- ) {
					// utable[k] = utable[k-2]
					lua_geti( L, utable, k-2 );
					lua_seti( L, utable, k );
				}
				setfield( L, j+2, rend+1, utable );
				setfield( L, j+1, rstart-1, utable );
			}
		}
	}	

	lua_pop( L, 2 );

	return 0;
}

static int getfiledataoff( lua_State *L ) {
	
	const char *path = luaL_checkstring(L, -1);
	const char *path2 = luaL_checkstring(L, -2);

	printf( "There are %d elements in stack at start\n", lua_gettop( L ) );
	printf( "path %s %zd, path2 %s %zd\n", path, strlen(path), path2, strlen(path2) );	


	lua_pushlstring( L, "109.12", 5 );
	lua_pushnumber( L, 6 );
	printf( "There are %d elements in stack at start\n", lua_gettop( L ) );
	return 2;
}

void do_something( lua_State *L ) {

	const char* ts;
	char        ts_cpy[128];

	/* Get the trusted server addr as a string */
	lua_getglobal( L, "trusted_server" );
	if( !lua_isstring( L, -1 ) ) {
		printf( "'trusted_server' should be a string\n" );
		return;
	}

	ts = luaL_checkstring( L, -1 );
	strcpy( ts_cpy, ts );
	printf( "'trusted server' is %s\n", ts_cpy );
}

static void usage(void) {
	printf( "./lua_program FILENAME\n"
			"     FILENAME  < %d B\n", POLICY_MAX_SIZE );
}

int main( int argc, char **argv ) {
	FILE 	   *fp;
	char 	    buffer[POLICY_MAX_SIZE];
	size_t 	    sz;
	lua_State  *L;
	int         ret;
	int         res;

	if( argc != 2 ) {
		usage();
		return 0;
	}

	fp = fopen( argv[1], "r+" );

	/* Get the policy file size */
	fseek( fp, 0L, SEEK_END );
	sz = ftell(fp);

	if( sz > POLICY_MAX_SIZE ) {
		usage();
		return 0;
	}
	fseek( fp, 0L, SEEK_SET );

	/* Read the file into buffer */
	memset( buffer, 0, POLICY_MAX_SIZE );
	sz = fread( buffer, sizeof(char), sz, fp );
	fclose(fp);

	//printf( "Policy: %zd B\n%s\n", sz, buffer );

	/* Call Lua interpreter */
	L = luaL_newstate();
	luaL_openlibs(L);

	/* Load Lua code */
	ret = luaL_loadstring( L, buffer ) || lua_pcall( L, 0, 0, 0 );
	if( ret != LUA_OK ) {
		printf( "Cannot run lua file: %s >> error code %d\n", argv[1], ret );
		lua_close( L );
		return 0;
	}

	memset( buffer, 0, POLICY_MAX_SIZE );

	//printf( "There are %d elements in stack at start\n", lua_gettop( L ) );

	/* Export a C function -> getfiledataoff() */
	//lua_pushcfunction( L, getfiledataoff );
    //lua_setglobal( L, "getfiledataoff" );	
	//lua_pushcfunction( L, redact_offset );
	//lua_setglobal( L, "redact_offset" );

	//printf( "There are %d elements in stack at start\n", lua_gettop( L ) );

	//do_something( L );

	//printf( "There are %d elements in stack at start\n", lua_gettop( L ) );
	lua_settop( L, 0 );

	printf( "There are %d elements in stack at start\n", lua_gettop( L ) );
	/* Call lua policy function */
	lua_getglobal( L, "policy" );
	lua_pushnumber( L, 1  ); /* policy takes a number argument */
	ret = lua_pcall( L, 1, 2, 0 );
	if( ret != LUA_OK ) {
		printf( "Error running function  'policy': %s\n", 
				lua_tostring( L, -1 ) );
		lua_settop( L, 0 );
		return 0;
	}
/*
	if( !lua_isboolean( L, -2 ) ) {
		printf( "Function  'policy' must return a boolean\n" );
		return 0;
	}

	printf( "There are %d elements in stack at start\n", lua_gettop( L ) );
	res = lua_toboolean( L, -2 );
	lua_pop( L, 1 );

	printf( "There are %d elements in stack at start\n", lua_gettop( L ) );
	printf( "Function 'policy' evaluated to %s\n", 
			res == 1 ? "true" : "false" );

	fp = fopen( argv[2], "r+" );
*/
	/* Get the policy file size */
/*
	fseek( fp, 0L, SEEK_END );
	sz = ftell(fp);

	if( sz > POLICY_MAX_SIZE ) {
		usage();
		return 0;
	}
	fseek( fp, 0L, SEEK_SET );
*/
	/* Read the file into buffer */
/*
	memset( buffer, 0, POLICY_MAX_SIZE );
	sz = fread( buffer, sizeof(char), sz, fp );
	fclose(fp);
*/
	//printf( "Policy: %zd B\n%s\n", sz, buffer );

	/* Load Lua code */
/*
	ret = luaL_loadstring( L, buffer ) || lua_pcall( L, 0, 0, 0 );
	if( ret != LUA_OK ) {
		printf( "Cannot run lua file: %s >> error code %d\n", argv[2], ret );
		lua_close( L );
		return 0;
	}

	memset( buffer, 0, POLICY_MAX_SIZE );

	lua_getglobal( L, "policy" );
	lua_pushnumber( L, 1 ); */ /* policy takes a number argument */
/*
	ret = lua_pcall( L, 1, 1, 0 );
	if( ret != LUA_OK ) {
		printf( "Error running function  'policy': %s\n", 
				lua_tostring( L, -1 ) );
		lua_settop( L, 0 );
		return 0;
	}
*/
	lua_close( L );
	return 0;
}
