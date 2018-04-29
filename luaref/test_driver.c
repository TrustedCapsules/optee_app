#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <capsuleCommon.h>
#include <capsulePolicy.h>

#include "fakeoptee.h"
	
char fileData[] = "a really long string of random stuff";

RESULT getState_Credential( const char* key, size_t keyLen, 
							char* value, size_t* valueLen ) {
	UNUSED( keyLen );
	printf( "Lua getState()->%s\n", key );
	char credential[] = "Dr. James Allison";
	memcpy( value, credential, strlen( credential ) );
	*valueLen = strlen( credential );
	return NIL;
}

RESULT getState_KeyError( const char* key, size_t keyLen, 
			    		   char* value, size_t* valueLen ) {
	UNUSED( keyLen );
	UNUSED( value );
	UNUSED( valueLen );
	printf( "Lua getState()->%s\n", key );
	
	return ERROR_KEY_NOT_FOUND;
}

RESULT getState_ServerReplyError( const char* key, size_t keyLen, 
			    		  	 char* value, size_t* valueLen ) {
	UNUSED( keyLen );
	UNUSED( value );
	UNUSED( valueLen );
	printf( "Lua getState()->%s\n", key );
	
	return ERROR_SERVER_REPLY;
}
RESULT getState_ServerPipeError( const char* key, size_t keyLen, 
			    		   char* value, size_t* valueLen ) {
	UNUSED( keyLen );
	UNUSED( value );
	UNUSED( valueLen );
	printf( "Lua getState()->%s\n", key );
	
	return ERROR_SERVER_BROKEN_PIPE;
}

RESULT getState_DataError( const char* key, size_t keyLen, 
			    		   char* value, size_t* valueLen ) {
	UNUSED( keyLen );
	UNUSED( value );
	UNUSED( valueLen );
	printf( "Lua getState()->%s\n", key );
	
	return ERROR_DATA_CORRUPTED;
}

RESULT getState_AccessError( const char* key, size_t keyLen, 
			    		   char* value, size_t* valueLen ) {
	UNUSED( keyLen );
	UNUSED( value );
	UNUSED( valueLen );
	printf( "Lua getState()->%s\n", key );
	
	return ERROR_ACCESS_DENIED;
}

RESULT setState_Credential( const char* key, size_t keyLen, 
							const char* value, size_t valueLen ) {
	UNUSED( keyLen );
	UNUSED( valueLen );
	printf( "Lua setState()->%s: %s\n", key, value );
	return NIL;
}

RESULT setState_ServerPipeError( const char* key, size_t keyLen, 
					   const char* value, size_t valueLen ) {
	UNUSED( keyLen );
	UNUSED( valueLen );
	printf( "Lua setState()->%s: %s\n", key, value );
	return ERROR_SERVER_BROKEN_PIPE;
}

RESULT setState_AccessError( const char* key, size_t keyLen, 
					   const char* value, size_t valueLen ) {
	UNUSED( keyLen );
	UNUSED( valueLen );
	printf( "Lua setState()->%s: %s\n", key, value );
	return ERROR_ACCESS_DENIED;
}

RESULT setState_ServerReplyError( const char* key, size_t keyLen, 
					   const char* value, size_t valueLen ) {
	UNUSED( keyLen );
	UNUSED( valueLen );
	printf( "Lua setState()->%s: %s\n", key, value );
	return ERROR_SERVER_REPLY;
}

__attribute__((noreturn)) void deleteCapsule() {
	printf( "Lua deleteCapsule()->do not return\n" );
	exit( -1 );
}

RESULT update_ServerReplyError( lua_State *L ) {
	UNUSED( L );
	printf( "Lua update()->Server reply error\n" );
	return ERROR_SERVER_REPLY;
}

RESULT update_ServerPipeError( lua_State *L ) {
	UNUSED( L );
	printf( "Lua update()->Cannot contact server\n" );
	return ERROR_SERVER_BROKEN_PIPE;
}

RESULT update_DataError( lua_State *L ) {
	UNUSED( L );
	printf( "Lua update()->Data Corrupted\n" );
	return ERROR_DATA_CORRUPTED;
}

RESULT update_FailError( lua_State *L ) {
	UNUSED( L );
	printf( "Lua update()->Update Failed\n" );
	return ERROR_UPDATE_FAILURE;	
}

RESULT update_None( lua_State *L ) {
	UNUSED( L );
	printf( "Lua update()->No Update\n" );
	return NIL;
}

RESULT update( lua_State *L ) {
	printf( "Lua update()->Successful\n" );
	luaL_error( L, POLICY_UPDATED_ERROR_MSG );
	return UPDATED;
}

RESULT location_incorrect( int* longitude, int* latitude ) {
	*longitude = 10;
	*latitude = 15;
	printf( "Lua location()->incorrect coord (long %d, lat %d)\n", 
			*longitude, *latitude );
	return NIL;
}

RESULT location_correct( int* longitude, int* latitude ) {
	*longitude = 123;
	*latitude = 15;
	printf( "Lua location()->correct coord (long %d, lat %d)\n", 
			*longitude, *latitude );
	return NIL;
}

RESULT location_NoService( int* longitude, int* latitude ) {
	*longitude = 10;
	*latitude = 15;
	printf( "Lua location()->No Service\n" );
	return POLICY_ERROR_LOC_NOT_AVAIL;
}

RESULT time_incorrect( uint32_t* ts ) {
	*ts = 1000000;
	printf( "Lua time()->curr_time %u\n", *ts );
	return NIL;
}

RESULT time_correct( uint32_t* ts ) {
	*ts = 1523338400;
	printf( "Lua time()->curr_time %u\n", *ts );
	return NIL;
}

RESULT time_NoService( uint32_t* ts ) {
	UNUSED( ts );
	printf( "Lua time()->No Service\n" );
	return POLICY_ERROR_TIME_NOT_AVAIL;
}

RESULT redact( const size_t start, const size_t end, 
			   const char* replStr, size_t len ) {
	printf( "Lua redact()->start: %zu (B), end: %zu (B), repl: %s (%zu B)\n",
			start, end, replStr, len );
	return NIL;
}

RESULT redact_failure( const size_t start, const size_t end, 
					   const char* replStr, size_t len ) {
	UNUSED( start );
	UNUSED( end );
	UNUSED( replStr );
	UNUSED( len );
	printf( "Lua redact()->failure\n" );
	return ERROR_REDACT_FAILURE;
}

RESULT appendToBlacklist( const char* key, size_t len ) {
	printf( "Lua appendToBlacklist()->%s (%zu B)\n", key, len );
	return NIL; 
}

RESULT appendToBlacklist_failure( const char* key, size_t len ) {
	UNUSED( key );
	UNUSED( len );
	printf( "Lua appendToBlacklist()->failure\n" );
	return ERROR_APPEND_BLACKLIST;
}

RESULT removeFromBlacklist( const char* key, size_t len ) {
	printf( "Lua appendToBlacklist()->%s (%zu B)\n", key, len );
	return NIL; 
}

RESULT removeFromBlacklist_failure( const char* key, size_t len ) {
	UNUSED( key );
	UNUSED( len );
	printf( "Lua removeFromBlacklist()->failure\n" );
	return ERROR_REMOVE_BLACKLIST;
}

int capsuleLength() {
	size_t n = strlen( fileData );
	printf( "Lua capsuleLength()->%zu\n", n );
	return n;
}

int capsuleLength_error() {
	return -1;
}

int readCapsuleData( char** buf, size_t len, size_t offset ) {
	size_t lenData = strlen( fileData );
	
	if ( offset > lenData ) {
		return 0;
	}

	size_t copyLen = offset + len > lenData ? lenData - offset : len;  
	*buf = fileData + offset;

	printf( "Lua readCapsuleData()->%s (%zu B)\n", *buf, copyLen );	
	return copyLen;
}

int readCapsuleData_error( char** buf, size_t len, size_t offset ) {
	UNUSED( buf );
	UNUSED( len );
	UNUSED( offset );
	printf( "Lua readCapsuleData()->failure\n" );	
	return -1;
}
