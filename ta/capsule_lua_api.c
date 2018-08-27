#include <stdlib.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>

#include <capsulePolicy.h>
#include <capsuleCommon.h>

#include "capsule_ta.h"
#include "capsule_lua_api.h"
#include "capsule_structures.h"
#include "capsule_op.h"
#include "lua_helpers.h"
#include "capsule_lua_ext.h"

// TEE_getLocation queries the device location from 
//		WHERE_REMOTE_SERVER - remote server 
//		WHERE_LOCAL_DEVICE - local device
// If an error occurs, ERROR_LOC_NOT_AVAIL is returned
RESULT TEE_getLocation( int* longitude, int* latitude, const WHERE w ) {
	TEE_GPS gps;
	switch( w ) {
	case WHERE_REMOTE_SERVER:
		return NIL;
	case WHERE_LOCAL_DEVICE:
		TEE_GetGPS( &gps ); // Should probably modify for error code
		*longitude = gps.longitude;
		*latitude = gps.latitude;
		return NIL;
	default:
		return ERROR_UNKNOWN_WHERE;
	}
}

// TEE_getTime queries the current time from 
//		WHERE_REMOTE_SERVER - remote server 
//		WHERE_LOCAL_DEVICE - local device
// If an error occurs, ERROR_TIME_NOT_AVAIL is returned
// If no error occurs, NIL is returned
RESULT TEE_getTime(lua_State *L, uint32_t *ts, const WHERE w)
{
	TEE_Time t;
	TEE_Result res = TEE_SUCCESS;
	char *ip;
	uint16_t port;

	switch( w ) {
	case WHERE_REMOTE_SERVER:
		res = lua_get_server_ip_port(L, ip, &port);
		CHECK_SUCCESS(res, "failed to get trusted server information from policy");
		res = get_time_from_remote(ip, port, &t);
		if(res !=TEE_SUCCESS){
			return ERROR_TIME_NOT_AVAIL;
		}
		return NIL;
	case WHERE_LOCAL_DEVICE:
		TEE_GetREETime( &t );
		*ts = t.seconds;
		return NIL;
	default:
		return ERROR_UNKNOWN_WHERE;
	}
}

// TEE_getState returns the value specified by key from 
//		WHERE_REMOTE_SERVER - remote server 
//		WHERE_SECURE_STORAGE - local secure storage
//      WHERE_CAPSULE_META - trusted capsule metadata
// If an error occurs, following error may be returned
//		ERROR_KEY_NOT_FOUND  		- key not found
//		ERROR_ACCESS_DENIED  		- cannot access secure storage 
//		ERROR_DATA_CORRUPTED 		- received encrypted data did not 
//									  match hash
//		ERROR_SERVER_REPLY     		- server reply an error occured
// 		ERROR_SERVER_BROKEN_PIPE 	- cannot contact server
RESULT TEE_getState(lua_State *L, const char *key, size_t keyLen, char *value, size_t *valueLen,
					const WHERE w)
{
	TEE_Result res ;
	char *ip_addr;
	uint16_t port;

	switch( w ) {
	case WHERE_SECURE_STORAGE:
		// Get state from capsule state file
		return do_get_state(key, value, valueLen);
					   
	case WHERE_REMOTE_SERVER:
		res = lua_get_server_ip_port(L, ip_addr, &port);
		MSG( "failed to get trusted server information from policy");
		return do_get_remote_state((unsigned char*) key, (unsigned char*) value, 
									(uint32_t) keyLen, (uint32_t) valueLen, ip_addr, port);
		
	case WHERE_CAPSULE_META:
		//DONE this is a read to the capsule metadata hashtable
		return do_get_capsule_state((unsigned char*) key, (unsigned char*) value, (uint32_t) valueLen);
	
	default:
		return ERROR_UNKNOWN_WHERE;
	}
}

// TEE_setState writes the value 
//		WHERE_REMOTE_SERVER - remote server 
//		WHERE_SECURE_STORAGE - local secure storage
//      WHERE_CAPSULE_META - trusted capsule metadata
// If an error occurs, following error may be returned
//		ERROR_KEY_NOT_FOUND  		- key not found
//		ERROR_ACCESS_DENIED  		- cannot access secure storage 
//		ERROR_SERVER_REPLY     		- server reply an error occured
// 		ERROR_SERVER_BROKEN_PIPE 	- cannot contact server
RESULT TEE_setState(lua_State *L, const char *key, size_t keyLen, const char *value, size_t valueLen,
					const WHERE w)
{
	TEE_Result res;
	char *ip_addr;
	uint16_t port;

	switch( w ) {
	case WHERE_SECURE_STORAGE:
		// Since only the capsule specific secure storage file is the only modifiable state file, 
		//we don't need to check for the device file key, unless we want to claim those as special?
		return do_set_state( (unsigned char*) key, (uint32_t) keyLen,  (unsigned char*) value,  (uint32_t) valueLen);
		
	case WHERE_REMOTE_SERVER:
		res = lua_get_server_ip_port(L, ip_addr, &port);
		MSG("failed to get trusted server information from policy");
		return do_set_remote_state( (unsigned char*) key, (unsigned char*) value, (uint32_t) keyLen, (uint32_t) valueLen, ip_addr, port);

	case WHERE_CAPSULE_META:
		return do_set_capsule_state((unsigned char *)key, (unsigned char *)value, (uint32_t) keyLen, (uint32_t) valueLen);

	default:
		return ERROR_UNKNOWN_WHERE;
	}
}

// TEE_deleteCapsule deletes the trusted capsule, capsule-specific storage file and 
// kills the trusted capsule session.
RESULT TEE_deleteCapsule(void) {
	/* The solution below is inelegant, but it gets the
	 * job done, even against TOCTTOU attacks.
	 * 
	 * 1) Delete the statefile for this capsule
	 * 2) Zero the entire capsule form header down
	 * 3) Call unlink on the file
	 * 4) TEE_Panic out of the trusted capsule session
	 */

	int fd;
	size_t file_length, nw = 0;
	char* zero_block;
	uint32_t offset = 0;
	TEE_Result res;

	TEE_CloseAndDeletePersistentObject( stateFile);
	res = TEE_SimpleOpen( capsule_name, &fd );
	if ( fd < 0 || res != TEE_SUCCESS ) {
		// File does not exist
		goto delete_file_exit;
	}

	// TODO: error checks and do we store file length anywhere?
	//       avoiding an lseek would be nice
	res = TEE_SimpleLseek( fd, 0, TEE_DATA_SEEK_END, &file_length );

	// This might need to be TEE_Malloc
	zero_block = TEE_Malloc( file_length*sizeof( char ), 0 );
	res = TEE_SimpleWrite( fd, zero_block, file_length, &nw, offset);

	TEE_Free( zero_block );
	TEE_SimpleClose( fd );
	TEE_SimpleUnlink( capsule_name );
	
delete_file_exit:
	// MSG( "Deleting file %s...", capsule_name );
	TEE_Panic(0);
	return NIL;
}

// TEE_originalCapsuleLength returns the length of the trusted capsule data.
int TEE_capsuleLength( CAPSULE w ) {
	switch( w ) {
		case ORIGINAL: 
			return cap_head.data_len;
		case NEW: 
			return cap_head.data_shadow_len;
		default: 
			break;
	}
	return -1;
}

// TEE_appendToBlacklist appends key to list of states not to log for
//		BL_TRUSTED_APP - trusted app internal optional states
//		BL_SECURE_STORAGE - secure storage states in capsule-specific file
//		BL_CAPSULE_META - metadata states in trusted capsule
// Returns ERROR_APPEND_BLACKLIST in case of error.
//TODO: I am not implementing the TA blacklist. It is fairly straightforward to do, 
//		but I don't see any state that is TA specific
RESULT TEE_appendToBlacklist( const char* str, size_t strLen, const WHERE w ) {
	TEE_Result res = TEE_SUCCESS;
	res = do_append_blacklist (str,strLen, w);
	if(res != TEE_SUCCESS)
	{
		return ERROR_APPEND_BLACKLIST;
	}
	return res;
}

// TEE_removeFromBlacklist appends key to list of states not to log for
//		BL_TRUSTED_APP - trusted app internal optional states
//		BL_SECURE_STORAGE - secure storage states in capsule-specific file
//		BL_CAPSULE_META - metadata states in trusted capsule
// Returns ERROR_REMOVE_BLACKLIST in case of error.
RESULT TEE_removeFromBlacklist( const char* str, size_t strLen, const WHERE w ) {
	TEE_Result res = TEE_SUCCESS;
	res = do_append_blacklist(str, strLen, w);
	if (res != TEE_SUCCESS)
	{
		return ERROR_REMOVE_BLACKLIST;
	}
	return res;
}

// TEE_redact writes a redaction record into a global trusted app redaction buffer.
// It specifies the start/end byte offsets in the data section of the trusted 
// capsule and replaces it with the Lua string specified by the var replaceStr. 
// Returns: NIL - successfully appended the redaction record
//			ERROR_REDACT_FAILURE - could not append the redaction record

RESULT TEE_redact( const size_t start, const size_t end, 
				   const char* replaceStr, size_t len ) {
	
	SYSCALL_OP op = TEE_get_op();
	TEE_Result res = TEE_SUCCESS;

	if (op == OPEN_OP)
	{
		//redact the shadow buffer and copy contents to redact buffer,
		//set the global read only flag.
		char *newBuf;
		
		res = do_redact(cap_head.data_shadow_buf, &newBuf, replaceStr, start, end, len);
		TEE_Realloc(cap_head.data_shadow_buf, strlen(*newBuf));
		TEE_MemMove(cap_head.data_shadow_buf, *newBuf, strlen(*newBuf));
		TEE_Free(newBuf);
		
		//Set read_only flag;
		cap_head.is_read_only = true;
	}
	else if(op == CLOSE_OP)
	{
		//Discard the contents of the shadow buffer.
		cap_head.data_shadow_buf = TEE_Realloc(cap_head.data_shadow_buf, cap_head.data_len);
		TEE_MemMove(cap_head.data_shadow_buf, cap_head.data_buf, cap_head.data_len);
	}
	//TODO: what kind of errors can pop-up here?
	//Check for malloc, move and realloc errors.

	return res;
	
}

// TEE_updatePolicy queries the remote server for policy updates. 
// Return: 
//	UPDATED 					- successful policy update
//	NIL     					- no update
//  ERROR_SERVER_REPLY  		- server replied with an error
//	ERROR_SERVER_BROKEN_PIPE	- could not contact remote server 
//	ERROR_DATA_CORRUPTED		- received policy did not match its hash
//	ERROR_UPDATE_FAILURE		- general update failure that cannot be 
//								  classified by above
RESULT TEE_updatePolicy( lua_State *L ) {
	//-------FILL-IN HERE----------
	// Suggested design: see current luaE_checkpolicychange. We make the following
	// changes:
	// 	(1) An updated policy directly returns to policy reload, currently we update
	//		a flag in Lua and leave return up to the policy. 
	//	(2) No longer need to check for remote delete. This is subsumed under policy
	//		change.
	//	(3) Policy buffer in trusted world is wiped and re-written with new policy.
	//		Whether this is durably written back to the trusted capsule can be the
	//		implementer's choice. As long as the reload policy is from the policy 
	//		buffer, the policy engine will always execute the latest policy. 
	//	(4) NOTE: we recommend that states that are checked to verify whether to call
	//		updatePolicy() should be from secure trusted sources and/or stored in the
	//		trusted capsule metadata. Since writes to local secure storage are best
	//		effort (Normal World may pretend the write happened), it provides 
	//		attackers with a mechanism to evade policy updates.
	//TODO:
	UNUSED( L );
	return NIL;
	//----------------------------
}

// TEE_readCapsuleData reads 'len' bytes from 'offset' bytes from the beginning of
//	NEW - new capsule data
//	ORIGINAL - original capsule data
// Returns the number of bytes read. 
//	If offset is past the end of the file, 0 is returned. 
//  If an error occurs, -1 is returned. 
int TEE_readCapsuleData( char** buf, size_t len, size_t offset, CAPSULE w ) {
	// TODO: Double check these mallocs work. Could seg fault. Also, the memory should get freed somewhere???
	switch( w ) {
	case NEW:
		if (offset + len > cap_head.data_shadow_len) {
			return 0;
		}
		// Allocate space
		*buf = TEE_Malloc(len, 0);
		TEE_MemMove(buf, cap_head.data_shadow_buf + offset, len);
		return len;
	case ORIGINAL:
		if (offset + len > cap_head.data_len) {
			return 0;
		}
		// Allocate space
		*buf = TEE_Malloc(len, 0);
		TEE_MemMove(buf, cap_head.data_buf + offset, len);
		return len;
	default: 
		break;
	}
	return -1;
	//-----------------------------
}

// TEE_get_op returns the current operation being evaluated. We cannot fetch this
// from Lua s it exists there only as a local var, therefore we must fetch this from
// optee app.
SYSCALL_OP TEE_get_op(void) {
	return fuse_op;
}

TEE_Result lua_get_server_ip_port(lua_State *L, char *ts, int *port)
{

	int res = TEE_SUCCESS;
	const char *temp;
	size_t len;

	lua_getglobal(L, SERVER_IP);
	if (!lua_isstring(L, -1))
	{
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS(res, "'%s' should be a string", SERVER_IP);
	}

	temp = lua_tolstring(L, -1, &len);
	memcpy(ts, temp, len);
	lua_pop(L, 1);

	lua_getglobal(L, SERVER_PORT);
	if (!lua_isinteger(L, -1))
	{
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS(res, "'%s' should be an integer", SERVER_PORT);
	}

	*port = lua_tointeger(L, -1);
	lua_pop(L, 1);

	return TEE_SUCCESS;
}
