#include <stdlib.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <capsulePolicy.h>

#include "capsule_lua_api.h"

// TEE_getLocation queries the device location from 
//		WHERE_REMOTE_SERVER - remote server 
//		WHERE_LOCAL_DEVICE - local device
// If an error occurs, ERROR_LOC_NOT_AVAIL is returned
RESULT TEE_getLocation( int* longitude, int* latitude, const WHERE w ) {
	switch( w ) {
	case WHERE_REMOTE_SERVER:
		// ---------FILL-IN HERE----------
		return (*dummy_location_fn)( longitude, latitude );
		// --------------------------
	case WHERE_LOCAL_DEVICE:
		// ---------FILL-IN HERE----------
		return (*dummy_location_fn)( longitude, latitude );
		// --------------------------
	default:
		return ERROR_LOC_NOT_AVAIL;
	}
	return NIL;
}

// TEE_getTime queries the current time from 
//		WHERE_REMOTE_SERVER - remote server 
//		WHERE_LOCAL_DEVICE - local device
// If an error occurs, ERROR_TIME_NOT_AVAIL is returned
RESULT TEE_getTime( uint32_t* ts, const WHERE w ) {
	switch( w ) {
	case WHERE_REMOTE_SERVER:
		// ---------FILL-IN HERE----------
		return (*dummy_time_fn)( ts );
		// --------------------------
	case WHERE_LOCAL_DEVICE:
		// ---------FILL-IN HERE----------
		return (*dummy_time_fn)( ts );
		// --------------------------
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
		return (*dummy_getState_fn)( key, keyLen, value, valueLen );
		// --------------------------
	case WHERE_REMOTE_SERVER:
		// ---------FILL-IN HERE----------
		// Suggested design: An RPC request is sent to the remote server. The server
		// replies with the value or error code. Connection is closed. The 
		// communication is protected by the same key used to encrypt the trusted 
		// capsule and is also protected by a random nonce, to match requests with 
		// replies and to protect against replay attacks.  
		return (*dummy_getState_fn)( key, keyLen, value, valueLen );
		// --------------------------
	case WHERE_CAPSULE_META:
		// ---------FILL-IN HERE----------
		// Suggested design: for semantic simplicity, read to metadata can be done 
		// purely on the trusted world side. 
		return (*dummy_getState_fn)( key, keyLen, value, valueLen );
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
		// For simplicity, writes are written-back synchronously/durably to the 
		// trusted capsule secure storage without buffering. 
		return (*dummy_setState_fn)( key, keyLen, value, valueLen );
		// --------------------------
	case WHERE_REMOTE_SERVER:
		// ---------FILL-IN HERE----------
		// Suggested design: An RPC request is sent to the remote server. The server
		// replies with the success or error code. Connection is closed. The 
		// communication is protected by the same key used to encrypt the trusted 
		// capsule and is also protected by a random nonce, to match requests with 
		// replies and to protect against replay attacks.  
		return (*dummy_setState_fn)( key, keyLen, value, valueLen );
		// --------------------------
	case WHERE_CAPSULE_META:
		// ---------FILL-IN HERE----------
		// Suggested design: for simplicity, writes are written back durably to the 
		// trusted capsule with the origin trusted capsule data.
		return (*dummy_setState_fn)( key, keyLen, value, valueLen );
		// --------------------------
	default:
		return ERROR_ACCESS_DENIED;
	}
	return NIL;
}

// TEE_deleteCapsule deletes the trusted capsule, capsule-specific storage file and 
// kills the trusted capsule session.
RESULT TEE_deleteCapsule(void) {
	//---------FILL-IN HERE----------
	// Suggested design: see delete_file(). Previously remote server can call delete
	// file, however, that can be subsumed by a update to policy that calls 
	// deleteCapsule(). 
	
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
	zero_block = malloc( file_length*sizeof( char ) );
	memset( zero_block, 0, file_length );
	res = TEE_SimpleWrite( fd, zero_block, file_length, &nw, offset);

	free( zero_block );
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
			//---------FILL-IN HERE----------
			return (*dummy_capsuleLength_fn)();
			//------------------------------
		case NEW: 
			//---------FILL-IN HERE----------
			return (*dummy_capsuleLength_fn)();
			//------------------------------
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
	switch( w ) {
	case BL_TRUSTED_APP: 
		return (*dummy_appendBlacklist_fn)( str, strLen );
	case BL_SECURE_STORAGE:
		return (*dummy_appendBlacklist_fn)( str, strLen );
	case BL_CAPSULE_META:
		return (*dummy_appendBlacklist_fn)( str, strLen );
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
	switch( w ) {
	case BL_TRUSTED_APP: 
		return (*dummy_removeBlacklist_fn)( str, strLen );
	case BL_SECURE_STORAGE:
		return (*dummy_removeBlacklist_fn)( str, strLen );
	case BL_CAPSULE_META:
		return (*dummy_removeBlacklist_fn)( str, strLen );
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
	return (*dummy_redact_fn)( start, end, replaceStr, len );
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
	return (*dummy_update_fn)( L );
	//----------------------------
}

// TEE_readCapsuleData reads 'len' bytes from 'offset' bytes from the beginning of
//	NEW - new capsule data
//	ORIGINAL - original capsule data
// Returns the number of bytes read. 
//	If offset is past the end of the file, 0 is returned. 
//  If an error occurs, -1 is returned. 
int TEE_readCapsuleData( char** buf, size_t len, size_t offset, CAPSULE w ) {
	//-------FILL-IN HERE-----------
	switch( w ) {
	case NEW:
		return (*dummy_readCapsuleData_fn)( buf, len, offset );
	case ORIGINAL:
		return (*dummy_readCapsuleData_fn)( buf, len, offset );
	default: 
		break;
	}
	return -1;
	//-----------------------------
}

// TEE_get_op returns the current operation being evaluated. We cannot fetch this
// from Lua s it exists there only as a local var, therefore we must fetch this from
// optee app.
SYSCALL_OP TEE_get_op() {
	return op;
}
