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

// TEE_getLocation queries the device location from 
//		WHERE_REMOTE_SERVER - remote server 
//		WHERE_LOCAL_DEVICE - local device
// If an error occurs, ERROR_LOC_NOT_AVAIL is returned
RESULT TEE_getLocation( int* longitude, int* latitude, const WHERE w ) {
	TEE_GPS gps;
	switch( w ) {
	case WHERE_REMOTE_SERVER:
		// ---------FILL-IN HERE----------
		// 1. Send request to remote server for location
		// 2. Wait for response
		// TODO: is this even necessary as an option? Yes the remote server
		// is trusted, but wouldn't it just respond with the remote server
		// location? How can it get a trusted location of the device?

		return NIL;
		// --------------------------
	case WHERE_LOCAL_DEVICE:
		TEE_GetGPS( &gps ); // Should probably modify for error code
		*longitude = gps.longitude;
		*latitude = gps.latitude;
		return NIL;
	default:
		return ERROR_LOC_NOT_AVAIL;
	}
	return NIL;
}

// TEE_getTime queries the current time from 
//		WHERE_REMOTE_SERVER - remote server 
//		WHERE_LOCAL_DEVICE - local device
// If an error occurs, ERROR_TIME_NOT_AVAIL is returned
// If no error occurs, NIL is returned
RESULT TEE_getTime( uint32_t* ts, const WHERE w ) {
	TEE_Time t;
	switch( w ) {
	case WHERE_REMOTE_SERVER:
		// ---------FILL-IN HERE----------
		// 1. Send message to remote server to get it's time
		// 2. Wait for response
		// 3. Return time.
		//TODO: implement this.
		return NIL;
		// --------------------------
	case WHERE_LOCAL_DEVICE:
		TEE_GetREETime( &t ); // again error code
		*ts = t.seconds;
		return NIL;
	default:
		return ERROR_TIME_NOT_AVAIL;
	}
	return NIL;
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
RESULT TEE_getState( const char* key, size_t keyLen, char* value, size_t* valueLen, 
					 const WHERE w ) {
	TEE_Result getStateResult ;
	//TEE_Result resDeviceFile;
	UNUSED( keyLen );

	switch( w ) {
	case WHERE_SECURE_STORAGE:
		// ---------FILL-IN HERE----------
		// Suggested design: each trusted capsule can access two files - a common 
		// device specific file (read-only) and a capsule-specific file
		// (read/write). Both files are searched to find the given 'key'. The
		// capsule-specific file is created if no such file exists. 
		//
		// We enforce that a capsule that has been opened cannot be opened again
		// until the previous open has been closed. We can use the capsule-specific
		// file to achieve this by 1) ensuring only one OPTEE session can open the
		// capsule specific file at a time, 2) open creates an OPTEE session and 
		// close ends the OPTEE session - open calls are implied by session 
		// creation, 3) once a capsule specific file has been created, a record of 
		// such an event is written synchronously into the trusted capsule metadata
		// before at state is written to secure storage, 4) the capsule-specific 
		// file is named by the encrypted capsule-id.
		// 
		// Implementer can decide whether to cache on the secure world side.
		// --------------------------

		// Get state from capsule state file
		getStateResult  = do_get_state((unsigned char *)key, (unsigned char *)value, (uint32_t)valueLen);
		if(getStateResult  != TEE_SUCCESS){
			if (getStateResult  == TEE_ERROR_NOT_SUPPORTED){
				return ERROR_KEY_BAD_SIZE;
			}
			else if (getStateResult  == TEE_ERROR_ITEM_NOT_FOUND){
				return ERROR_KEY_NOT_FOUND;
			}else{
				return ERROR_ACCESS_DENIED; // Secure storage object not found or bad reads
			}
		}

		//FIXME: 	get state from device file. <--DONE, but not needed.
		//			return one of the values(which should be default) ?
		//resDeviceFile = go_get_device_state((unsigned char *)key, (unsigned char *)value, (uint32_t)valueLen);
			return NIL;
	case WHERE_REMOTE_SERVER:
		// ---------FILL-IN HERE----------
		// Suggested design: An RPC request is sent to the remote server. The server
		// replies with the value or error code. Connection is closed. The 
		// communication is protected by the same key used to encrypt the trusted 
		// capsule and is also protected by a random nonce, to match requests with 
		// replies and to protect against replay attacks.  
		return NIL; 
		// --------------------------
	case WHERE_CAPSULE_META:
		//DONE this is a read to the capsule metadata hashtable
		getStateResult = do_get_metadata((unsigned char *)key, (unsigned char *)value, (uint32_t)valueLen);
		//TODO:Error handling
		return NIL;
		// --------------------------
	default:
		return ERROR_ACCESS_DENIED;
	}
	return NIL;
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
RESULT TEE_setState( const char* key, size_t keyLen, const char* value, size_t valueLen, 
					 const WHERE w ) {
	TEE_Result res;

	switch( w ) {
	case WHERE_SECURE_STORAGE:
		// Since only the capsule specific secure storage file is the only modifiable state file, we don't need to check for the device file key, unless we want to claim those as special?
		res = do_set_state( (unsigned char*) key, (uint32_t) keyLen, (unsigned char*) value, (uint32_t) valueLen);

		// TODO: check error codes 

		return NIL;
	case WHERE_REMOTE_SERVER:
		// ---------FILL-IN HERE----------
		// Suggested design: An RPC request is sent to the remote server. The server
		// replies with the success or error code. Connection is closed. The 
		// communication is protected by the same key used to encrypt the trusted 
		// capsule and is also protected by a random nonce, to match requests with 
		// replies and to protect against replay attacks.
		//TODO: Implement this. 
		return NIL;
		
	case WHERE_CAPSULE_META:
		res = do_set_metadata ( (unsigned char*)key, (uint32_t)keyLen, (unsigned char *)value, (uint32_t) valueLen); 
		return NIL;
	default:
		return ERROR_ACCESS_DENIED;
	}
	return NIL;
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
	//------------------------------

delete_file_exit:
	// MSG( "Deleting file %s...", capsule_name );
	// TODO: why is the TEE_Panic necessary?
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
RESULT TEE_appendToBlacklist( const char* str, size_t strLen, const WHERE w ) {
	//---------FILL-IN HERE---------
	// Suggested design: a global buffer for storing each blacklist which is then
	// used during logging to record only states that are not in the blacklist.
	UNUSED( str );
	UNUSED( strLen );
	switch( w ) {
	case BL_TRUSTED_APP: 
		return NIL;
	case BL_SECURE_STORAGE:
		return NIL;
	case BL_CAPSULE_META:
		return NIL;
	default:
		return ERROR_APPEND_BLACKLIST;
	}
	//----------------------------
	return NIL;
}

// TEE_removeFromBlacklist appends key to list of states not to log for
//		BL_TRUSTED_APP - trusted app internal optional states
//		BL_SECURE_STORAGE - secure storage states in capsule-specific file
//		BL_CAPSULE_META - metadata states in trusted capsule
// Returns ERROR_REMOVE_BLACKLIST in case of error.
RESULT TEE_removeFromBlacklist( const char* str, size_t strLen, const WHERE w ) {
	//---------FILL-IN HERE---------
	// Suggested design: a global buffer for storing each blacklist which is then
	// used during logging to record only states that are not in the blacklist.
	UNUSED( str );
	UNUSED( strLen );
	switch( w ) {
	case BL_TRUSTED_APP: 
		return NIL;
	case BL_SECURE_STORAGE:
		return NIL;
	case BL_CAPSULE_META:
		return NIL;
	default:
		return ERROR_APPEND_BLACKLIST;
	}
	//----------------------------
	return NIL;
}

// TEE_redact writes a redaction record into a global trusted app redaction buffer.
// It specifies the start/end byte offsets in the data section of the trusted 
// capsule and replaces it with the Lua string specified by the var replaceStr. 
// Returns: NIL - successfully appended the redaction record
//			ERROR_REDACT_FAILURE - could not append the redaction record
RESULT TEE_redact( const size_t start, const size_t end, 
				   const char* replaceStr, size_t len ) {
	//-------FILL-IN HERE----------
	// Suggested design: 
	//	1) if replaceStr is "" or does not exist in Lua, default is to remove the 
	//	   redacted section.
	//	2) on open, the global buffer for redaction records is wiped clean before 
	//	   policy evaluation.
	//  3) on close, the global buffer is used to find the regions in the new 
	//	   capsule data that were redacted. The redacted regions need to be restored with
	//	   unredacted data from the original capsule data buffer. This needs to be done
	//	   before close policy evaluation.
	//  4) For memory management simplicity, a max length for the replacement string
	//	   length and a max number of redaction records in the global buffer can be 
	//	   set.
	UNUSED( start );
	UNUSED( end );
	UNUSED( replaceStr );
	UNUSED( len );
	return NIL;
	//-----------------------------
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
