#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "fakeoptee.h"
#include "capsule_lua_ext.h"
#include "lua_helpers.h"
#include "test_driver.h"

RESULT (*dummy_location_fn)(int* longitude, int* latitude);
RESULT (*dummy_time_fn)(uint32_t* ts);
RESULT (*dummy_getState_fn)( const char* key, size_t keyLen, 
							 char* value, size_t* len );
RESULT (*dummy_setState_fn)( const char* key, size_t keyLen, 
							 const char* value, size_t valueLen );
void   (*dummy_deleteCapsule_fn)(void);
int	   (*dummy_capsuleLength_fn)(void);
RESULT (*dummy_appendBlacklist_fn)( const char* key, size_t strLen );
RESULT (*dummy_removeBlacklist_fn)( const char* key, size_t strLen );
RESULT (*dummy_redact_fn)( const size_t start, const size_t end, 
						const char* replaceStr, size_t len );
RESULT (*dummy_update_fn)( lua_State *L );
int    (*dummy_readCapsuleData_fn)( char** buf, size_t len, size_t offset );

SYSCALL_OP op;

static void usage(void) {
	printf( "./lua_program POLICY\n" );
	printf( "POLICY < %d B\n", POLICY_MAX_SIZE );
}


// open_file reads the capsule policy at 'filename' into the provided 'buf' which
// has length 'len'
// returns: size of the file
size_t open_file( const char* filename, char *buf ) {
	FILE   *fp;
	size_t  sz;	

	fp = fopen( filename, "r+" );
	if ( fp == NULL ) {
		printf( "Could not read file %s\n", filename );
		return 0;
	}
	
	// Get the policy size 
	fseek( fp, 0L, SEEK_END );
	sz = ftell( fp );

	if( sz > POLICY_MAX_SIZE ) {
		usage();
		return 0;
	}

	// Read the file
	memset( buf, 0, POLICY_MAX_SIZE );
	fseek( fp, 0L, SEEK_SET );
	sz = fread( buf, sizeof(char), sz, fp );
	
	fclose( fp );
	return sz;
}

void test_get_var() {
	char	buffer[POLICY_MAX_SIZE];
	open_file( "policies/policy_basic.lua", buffer );

	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );
	
	lua_load_policy( L, buffer );

	// run lua policy - OPEN
	op = OPEN;
	lua_run_policy( L, OPEN );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is POLICY_ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	// run lua policy - CLOSE
	op = CLOSE;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is POLICY_NOT_ALLOW (%s)\n", 
			r, r == NOT_ALLOW ? "true" : "false" );

	// get server 
	int		port;
	char  	ipv4[16] = {0};
	size_t  ipv4_len = lua_get_server( L, ipv4, 16, &port );
	printf( "Evaluated policy server: %s:%d (ipv4 len=%zu)\n", ipv4, port, ipv4_len );

	// get open/close log
	bool log_open = lua_get_log( L, OPEN );
	bool log_close = lua_get_log( L, CLOSE );
	printf( "Evaluated policy log open: %s\n", log_open == 1 ? "true" : "false" );
	printf( "Evaluated policy log close: %s\n", log_close == 1 ? "true" : "false" );	

	// get comment
	char	comment[100];
	size_t  commentLength = lua_get_comment( L, comment, 100 );
	printf( "Evaluated policy comment: %s (%zu B)\n", comment, commentLength );
	
	char 	str[100];
	size_t  strLength = lua_get_string( L, POLICY_COMMENT, str, 100 );
	printf( "Evaluated policy string %s: %s (%zu B)\n", POLICY_COMMENT, str, strLength );

	// get policy version
	int 	version = lua_get_policy_version( L );
	printf( "Evaluated policy version: %d\n", version );	

	lua_close_context( &L );
}

void test_get_state( const char* file ) {
	char	buffer[POLICY_MAX_SIZE];
	open_file( file, buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );
	
	lua_load_policy( L, buffer );
	op = CLOSE;
	dummy_getState_fn = &getState_Credential;
	lua_run_policy( L, CLOSE );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_getState_fn = &getState_KeyError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_KEY_NOT_FOUND (%s)\n", 
			r, r == ERROR_KEY_NOT_FOUND ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_getState_fn = &getState_ServerReplyError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_SERVER_REPLY (%s)\n", 
			r, r == ERROR_SERVER_REPLY ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_getState_fn = &getState_ServerPipeError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_SERVER_BROKEN_PIPE (%s)\n", 
			r, r == ERROR_SERVER_BROKEN_PIPE ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_getState_fn = &getState_AccessError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_ACCESS_DENIED (%s)\n", 
			r, r == ERROR_ACCESS_DENIED ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_getState_fn = &getState_DataError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_DATA_CORRUPTED (%s)\n", 
			r, r == ERROR_DATA_CORRUPTED ? "true" : "false" );
	
	lua_close_context( &L );
}

void test_set_state( const char* file ) {
	char	buffer[POLICY_MAX_SIZE];
	open_file( file, buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );

	lua_load_policy( L, buffer );
	op = CLOSE;
	dummy_setState_fn = &setState_Credential;
	lua_run_policy( L, CLOSE );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_setState_fn = &setState_ServerReplyError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_SERVER_REPLY (%s)\n", 
			r, r == ERROR_SERVER_REPLY ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_setState_fn = &setState_ServerPipeError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_SERVER_BROKEN_PIPE (%s)\n", 
			r, r == ERROR_SERVER_BROKEN_PIPE ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_setState_fn = &setState_AccessError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_ACCESS_DENIED (%s)\n", 
			r, r == ERROR_ACCESS_DENIED ? "true" : "false" );
	
	lua_close_context( &L );
}

void test_location( const char* file ) {
	char	buffer[POLICY_MAX_SIZE];
	open_file( file, buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );
	lua_load_policy( L, buffer );

	dummy_location_fn = &location_incorrect;
	lua_run_policy( L, CLOSE );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is NOT_ALLOW (%s)\n", 
			r, r == NOT_ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_location_fn = &location_correct;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_location_fn = &location_NoService;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is POLICY_ERROR_LOC_NOT_AVAIL (%s)\n", 
			r, r == POLICY_ERROR_LOC_NOT_AVAIL ? "true" : "false" );
	
	lua_close_context( &L );
}

void test_time( const char* file ) {
	char	buffer[POLICY_MAX_SIZE];
	open_file( file, buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );
	lua_load_policy( L, buffer );

	dummy_time_fn = &time_incorrect;
	lua_run_policy( L, CLOSE );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_time_fn = &time_correct;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is NOT_ALLOW (%s)\n", 
			r, r == NOT_ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_time_fn = &time_NoService;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is POLICY_ERROR_TIME_NOT_AVAIL (%s)\n", 
			r, r == POLICY_ERROR_TIME_NOT_AVAIL ? "true" : "false" );
	

	lua_close_context( &L );
}

void test_delete_capsule() {
	char	buffer[POLICY_MAX_SIZE];
	open_file( "policies/policy_delete.lua", buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_load_policy( L, buffer );
	
	dummy_deleteCapsule_fn = &deleteCapsule;
	lua_add_ext( L );

	lua_run_policy( L, CLOSE );
	
	lua_close_context( &L );
}

void test_update() {
	char	buffer[POLICY_MAX_SIZE];
	open_file( "policies/policy_update.lua", buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_load_policy( L, buffer );
	lua_add_ext( L );

	dummy_update_fn = &update;
	int err = lua_run_policy( L, CLOSE );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy updated (%s) - rewind to pcall (%s)\n", 
			err == UPDATED ? "true" : "false", r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_update_fn = &update_ServerReplyError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_SERVER_REPLY (%s)\n", 
			r, r == ERROR_SERVER_REPLY ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_update_fn = &update_ServerPipeError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_SERVER_BROKEN_PIPE (%s)\n", 
			r, r == ERROR_SERVER_BROKEN_PIPE ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_update_fn = &update_DataError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_DATA_CORRUPTED (%s)\n", 
			r, r == ERROR_DATA_CORRUPTED ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_update_fn = &update_FailError;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ERROR_UPDATE_FAILURE (%s)\n", 
			r, r == ERROR_UPDATE_FAILURE ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_update_fn = &update_None;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is NIL (%s)\n", 
			r, r == NIL ? "true" : "false" );
	
	lua_close_context( &L );
}

void test_append_blacklist( const char* file ) {
	char	buffer[POLICY_MAX_SIZE];
	open_file( file, buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );
	lua_load_policy( L, buffer );
	
	dummy_appendBlacklist_fn = &appendToBlacklist;
	lua_run_policy( L, OPEN );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_appendBlacklist_fn = &appendToBlacklist_failure;
	lua_run_policy( L, OPEN );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is POLICY_ERROR_APPEND_BLACKLIST (%s)\n", 
			r, r == POLICY_ERROR_APPEND_BLACKLIST ? "true" : "false" );

	lua_close_context( &L );
}

void test_remove_blacklist( const char* file ) {
	char	buffer[POLICY_MAX_SIZE];
	open_file( file, buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );
	lua_load_policy( L, buffer );
	
	dummy_removeBlacklist_fn = &removeFromBlacklist;
	lua_run_policy( L, OPEN );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_removeBlacklist_fn = &removeFromBlacklist_failure;
	lua_run_policy( L, OPEN );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is POLICY_ERROR_REMOVE_BLACKLIST (%s)\n", 
			r, r == POLICY_ERROR_REMOVE_BLACKLIST ? "true" : "false" );

	lua_close_context( &L );
}

void test_redact() {
	char	buffer[POLICY_MAX_SIZE];
	open_file( "policies/policy_redact.lua", buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );
	lua_load_policy( L, buffer );
	
	dummy_redact_fn = &redact;
	op = OPEN;
	lua_run_policy( L, OPEN );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_redact_fn = &redact_failure;
	lua_run_policy( L, OPEN );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is POLICY_ERROR_REDACT_FAILURE (%s)\n", 
			r, r == POLICY_ERROR_REDACT_FAILURE ? "true" : "false" );

	lua_close_context( &L );
}

void test_new_capsule_length() {
	char	buffer[POLICY_MAX_SIZE];
	open_file( "policies/policy_new_capsule_length.lua", buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );
	
	lua_load_policy( L, buffer );
	dummy_capsuleLength_fn = &capsuleLength;
	op = CLOSE;
	lua_run_policy( L, CLOSE );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy CLOSE result %d is ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_capsuleLength_fn = &capsuleLength_error;
	op = CLOSE;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is NOT_ALLOW (%s)\n", 
			r, r == NOT_ALLOW ? "true" : "false" );
	
	lua_close_context( &L );
}

void test_orig_capsule_length() {
	char	buffer[POLICY_MAX_SIZE];
	open_file( "policies/policy_orig_capsule_length.lua", buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );
	
	lua_load_policy( L, buffer );
	dummy_capsuleLength_fn = &capsuleLength;
	op = OPEN;
	lua_run_policy( L, OPEN );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_capsuleLength_fn = &capsuleLength_error;
	op = OPEN;
	lua_run_policy( L, OPEN );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is NOT_ALLOW (%s)\n", 
			r, r == NOT_ALLOW ? "true" : "false" );
	
	lua_close_context( &L );
}

void test_read_new_capsule() {
	char	buffer[POLICY_MAX_SIZE];
	open_file( "policies/policy_read_new_capsule.lua", buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );
	
	lua_load_policy( L, buffer );
	dummy_readCapsuleData_fn = &readCapsuleData;
	dummy_capsuleLength_fn = &capsuleLength;
	op = CLOSE;
	lua_run_policy( L, CLOSE );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_readCapsuleData_fn = &readCapsuleData_error;
	dummy_capsuleLength_fn = &capsuleLength;
	op = CLOSE;
	lua_run_policy( L, CLOSE );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is NOT_ALLOW (%s)\n", 
			r, r == NOT_ALLOW ? "true" : "false" );
	
	lua_close_context( &L );
}

void test_read_orig_capsule() {
	char	buffer[POLICY_MAX_SIZE];
	open_file( "policies/policy_read_orig_capsule.lua", buffer );
	
	lua_State *L = NULL;
	lua_start_context( &L );

	lua_load_enumerations( L );
	lua_add_ext( L );
	
	lua_load_policy( L, buffer );
	dummy_readCapsuleData_fn = &readCapsuleData;
	dummy_capsuleLength_fn = &capsuleLength;
	op = OPEN;
	lua_run_policy( L, OPEN );
	int r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is ALLOW (%s)\n", 
			r, r == ALLOW ? "true" : "false" );
	
	lua_load_policy( L, buffer );
	dummy_readCapsuleData_fn = &readCapsuleData_error;
	dummy_capsuleLength_fn = &capsuleLength;
	op = OPEN;
	lua_run_policy( L, OPEN );
	r = lua_get_policy_result( L );
	printf( "Evaluated policy OPEN result %d is NOT_ALLOW (%s)\n", 
			r, r == NOT_ALLOW ? "true" : "false" );
	
	lua_close_context( &L );
}

int main( int argc, char** argv ) {
	UNUSED( argc );
	UNUSED( argv );
	
	// get Lua var
	// test_get_var();

	// getState - TRUSTED_APP, SECURE_STORAGE, CAPSULE_META
	// setState - TRUSTED_APP, SECURE_STORAGE, CAPSULE_META
	test_get_state( "policies/policy_get_state_capsule_metadata.lua" );
	test_get_state( "policies/policy_get_state_secure_storage.lua" );
	test_get_state( "policies/policy_get_state_remote_server.lua" );
	//test_set_state( "policies/policy_set_state_capsule_metadata.lua" );
	//test_set_state( "policies/policy_set_state_secure_storage.lua" );
	//test_set_state( "policies/policy_set_state_remote_server.lua" );

	// getLocation - LOCAL, REMOTE
	//test_location("policies/policy_location_device.lua");	
	//test_location("policies/policy_location_remote_server.lua");	

	// getTime - LOCAL, REMOTE
	//test_time("policies/policy_time_remote_server.lua");	
	//test_time("policies/policy_time_device.lua");	

	// readOriginalCapsuleData 
	// - need to test if Lua passes in a pointer or copies the contents
    // - if it copies -> dynamic memory allocation might fail, we should limit the 
	//   read size
	// - if it does not copy -> everything is fine since strings are immutable in Lua
	// originalCapsuleLength
	// readNewCapsuleData
	// - see readOriginalCapsuleData
	// newCapsuleLength
	//test_orig_capsule_length();
	//test_new_capsule_length();
	//test_read_orig_capsule();
	//test_read_new_capsule();	

	// updatePolicy
	// - need to test the use of lua_error to unwind the stack, recovery is reloading 
	//   the policy and re-evaluating
	//test_update();	

	// appendToBlacklist - TRUSTED_APP, SECURE_STORAGE, CAPSULE_META
	// removeFromBlacklist - TRUSTED_APP, SECURE_STORAGE, CAPSULE_META
	//test_append_blacklist( "policies/policy_log_bl_append_capsule_meta.lua" );	
	//test_append_blacklist( "policies/policy_log_bl_append_secure_storage.lua" );	
	//test_append_blacklist( "policies/policy_log_bl_append_trusted_app.lua" );	
	//test_remove_blacklist( "policies/policy_log_bl_remove_capsule_meta.lua" );	
	//test_remove_blacklist( "policies/policy_log_bl_remove_secure_storage.lua" );	
	//test_remove_blacklist( "policies/policy_log_bl_remove_trusted_app.lua" );	

	// redact
	//test_redact();
	
	// deleteCapsule
	test_delete_capsule();
	
}

