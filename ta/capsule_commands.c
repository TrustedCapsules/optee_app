#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <capsule.h>
#include <amessage.pb-c.h>
#include <serialize_common.h>
#include <lua.h>
#include <lauxlib.h>
#include "capsule_structures.h"
#include "capsule_commands.h"
#include "capsule_helper.h"
#include "capsule_op.h"
#include "capsule_lua_ext.h"
#include "capsule_ta.h"

/* UNUSED - This is a legacy function back in the days when we 
 * encrypted the AES key with an RSA key. This was later deemed 
 * excessive, but we leave the code here in the name of science
 */

TEE_Result register_rsa_key( uint32_t param_type, 
							 TEE_Param params[4] ) {
	
	/* We create a transient object handle for the RSA key
	 */
	ASSERT_PARAM_TYPE( 
			TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
							 TEE_PARAM_TYPE_MEMREF_INPUT,
							 TEE_PARAM_TYPE_NONE,
							 TEE_PARAM_TYPE_NONE ) );	

	return do_register_rsa( params[0].value.a, params[0].value.b,
		   		            params[1].memref.buffer, 
					        params[1].memref.size );	   
}
/* Register an AES key to to Trusted Application. At same time
 * the key is added to persistent storage. 
 */
TEE_Result register_aes_key( uint32_t param_type, 
				             TEE_Param params[4] ) {
	
	ASSERT_PARAM_TYPE( 
		TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
		    			 TEE_PARAM_TYPE_VALUE_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT ) 
	);
	
    return do_register_aes( params[0].value.a, 
							params[1].value.a,
							params[1].value.b, 
							params[0].value.b,
							params[2].memref.buffer, 
							params[2].memref.size,
							params[3].memref.buffer, 
							params[3].memref.size );
}

/* Sets a local state in the state file */
TEE_Result set_state( uint32_t param_type,
					  TEE_Param params[4] ) {

	TEE_Result res = TEE_SUCCESS;
	bool       close_after = false;

	ASSERT_PARAM_TYPE( 
		TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_VALUE_INPUT,
						 TEE_PARAM_TYPE_NONE ) );
	
	/* Open the state file for this trusted capsule */
	if( stateFile == TEE_HANDLE_NULL ) {
		close_after = true;
		res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE,
										&params[2].value.a, sizeof( uint32_t ),
										TEE_DATA_FLAG_ACCESS_READ | 
										TEE_DATA_FLAG_ACCESS_WRITE |
										TEE_DATA_FLAG_ACCESS_WRITE_META,	
										&stateFile );
		//MSG( "Opening statefile..." );
		if( res == TEE_ERROR_ITEM_NOT_FOUND ) {
			//MSG( "First activation...creating state file...0x%08x", params[2].value.a );
			res = TEE_CreatePersistentObject( TEE_STORAGE_PRIVATE,
											  &params[2].value.a, sizeof( uint32_t ),
											  TEE_DATA_FLAG_ACCESS_READ | 
											  TEE_DATA_FLAG_ACCESS_WRITE |
											  TEE_DATA_FLAG_ACCESS_WRITE_META,
											  0, NULL, 0, &stateFile );
			CHECK_GOTO( res, set_state_exit, "TEE_CreatePersistentObject() Error" );
			//MSG( "State file...0x%08x created", params[2].value.a );
		} else {
			CHECK_GOTO( res, set_state_exit, "TEE_OpenPersistentObject() Error" );
		}
	}

	res = do_set_state( params[0].memref.buffer, params[0].memref.size, 
					    params[1].memref.buffer, params[1].memref.size );
set_state_exit:
	if( close_after ) {
		TEE_CloseObject( stateFile );
		stateFile = TEE_HANDLE_NULL;
	}
	return res;

}

/* Gets a local state in the state file */
TEE_Result get_state( uint32_t param_type,
					  TEE_Param params[4] ) {

	TEE_Result res = TEE_SUCCESS;
	bool       close_after = false;

	ASSERT_PARAM_TYPE(
		TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_VALUE_INPUT,
						 TEE_PARAM_TYPE_NONE ) );

	/* Open the state file for this trusted capsule */
	if( stateFile == TEE_HANDLE_NULL ) {
		close_after = true;
		res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE,
										&params[2].value.a, sizeof( uint32_t ),
										TEE_DATA_FLAG_ACCESS_READ | 
										TEE_DATA_FLAG_ACCESS_WRITE |
										TEE_DATA_FLAG_ACCESS_WRITE_META,
										&stateFile );
		if( res == TEE_ERROR_ITEM_NOT_FOUND ) {
			MSG( "First activation...creating state file...%x", params[2].value.a );
			res = TEE_CreatePersistentObject( TEE_STORAGE_PRIVATE,
											  &params[2].value.a, sizeof( uint32_t ),
											  TEE_DATA_FLAG_ACCESS_READ | 
											  TEE_DATA_FLAG_ACCESS_WRITE | 
											  TEE_DATA_FLAG_ACCESS_WRITE_META,
											  0, NULL, 0, &stateFile );
			CHECK_GOTO( res, get_state_exit, "TEE_CreatePersistentObject() Error" );
			MSG( "State file...%x created", params[2].value.a );
		} else {
			CHECK_GOTO( res, get_state_exit, "TEE_OpenPersistentObject() Error" );
		}
	}
	res = do_get_state( params[0].memref.buffer, params[1].memref.buffer,
						params[1].memref.size );
	CHECK_GOTO( res, get_state_exit, "Do_get_state() Error" );

get_state_exit:
	if( close_after ) {
		TEE_CloseObject( stateFile );
		stateFile = TEE_HANDLE_NULL;
	}
	return res;
}

/* Opens a capsule for this TA session */
TEE_Result capsule_open( uint32_t param_type, 
				 				TEE_Param params[4] ) {
	
	TEE_Result 	  res = TEE_SUCCESS;
	unsigned char credential[STATE_SIZE];
	int 		  fd;

	ASSERT_PARAM_TYPE( 
		   TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT, 
							TEE_PARAM_TYPE_VALUE_INPUT,
							TEE_PARAM_TYPE_NONE, 
							TEE_PARAM_TYPE_NONE ) );

	/* Open the Trusted Capsule */	
	if( capsule_name == NULL ) {
		capsule_name = TEE_Malloc( params[0].memref.size + 1, 0 );
		memcpy( capsule_name, params[0].memref.buffer, 
				params[0].memref.size );
		capsule_name[ params[0].memref.size ] = '\0';
	
		DMSG( "Created new capsule session %s (%d B)", 
			 capsule_name, params[0].memref.size );
	} else {
		if( strncmp( capsule_name, 
					 params[0].memref.buffer, 
					 strlen( capsule_name ) ) != 0 ) {
			DMSG( "Input name does not match capsule name %s", capsule_name );
			return TEE_ERROR_NOT_SUPPORTED;
		}
	}
	DMSG( "Opening Trusted Capsule session...%s for %d/%d", 
		  capsule_name, params[1].value.a, params[1].value.b );

	res = TEE_SimpleOpen( capsule_name, &fd );
    if( res != TEE_SUCCESS) {
	    if( fd < 0 ) {
		    MSG( "TEE_SimpleOpen() cannot open %s", capsule_name );
		    return res;
	    }
        MSG( "TEE_SimpleOpen() cannot open %s\n\t returned fd %d", capsule_name, fd );
        return res;

    }

	res = do_open( fd, params[1].value.a, params[1].value.b );
	CHECK_GOTO( res, capsule_open_exit, "Do_open() Error" );

	if( Lstate == NULL ) {
		DMSG( "Initializing Interpreter..." );
		lua_start_context( &Lstate );
		DMSG( "Loading policy..." );
        res = do_load_policy( fd );
		CHECK_GOTO( res, capsule_open_exit, "Do_load_policy() Error" );
		DMSG( "Adding lua ext..." );
        res = add_lua_ext( Lstate );
		CHECK_GOTO( res, capsule_open_exit, "Add_lua_ext() Error" );
	}

	/* Open the state file for this trusted capsule */
	if( stateFile == TEE_HANDLE_NULL ) {
        DMSG( "Opening state file..." );
		res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE,
										&symm_id, sizeof( uint32_t ),
										TEE_DATA_FLAG_ACCESS_READ | 
										TEE_DATA_FLAG_ACCESS_WRITE |
										TEE_DATA_FLAG_ACCESS_WRITE_META,
										&stateFile );
		CHECK_GOTO( res, capsule_open_exit, "TEE_OpenPersistentObject() Error" );
	}	

    DMSG( "Getting state..." );
	res = do_get_state( (unsigned char*) TZ_CRED, credential, STATE_SIZE );
	CHECK_GOTO( res, capsule_open_exit, "Do_get_state() Error" );
   	curr_cred = *(int*)(void*)(credential);	

	curr_tgid = params[1].value.a;
	curr_fd = params[1].value.b;
	curr_len = 0;
	memset( curr_declassify_dest, 0, sizeof( curr_declassify_dest ) );

    DMSG( "Running policy..." );
	res = do_run_policy( fd, Lstate, POLICY_FUNC, OPEN_OP );
	if( res != TEE_SUCCESS ) {
        DMSG( "Error occurred with policy, closing..." );
		do_close( params[1].value.a, params[1].value.b );
	}

capsule_open_exit:
    DMSG( "Calling TEE_SimpleClose with %d", fd );
	TEE_SimpleClose( fd );
    DMSG( "Returning %x", res );
	return res;
}

/* Create another trusted capsule from the currently opened
 * capsule */
TEE_Result capsule_change_policy( uint32_t param_type, 
						   TEE_Param params[4] ) {
	
	TEE_Result 			res = TEE_SUCCESS;	
	int                 policy_fd = -1, capsule_fd = -1;
	char*               policyFile;
	size_t			    pollen;
    uint32_t            temp; // Placeholder b/c we don't always need ns

	ASSERT_PARAM_TYPE( 
			TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,
			  				 TEE_PARAM_TYPE_NONE,
							 TEE_PARAM_TYPE_NONE,
							 TEE_PARAM_TYPE_NONE ) );
	
	/* Check if we are in a capsule session */
	if( capsule_name == NULL ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Capsule_change_policy() no capsules opened" );
	}
	
	/* Check of a key was found to encrypt this capsule with */
	if( key_not_found(symm_iv, symm_id, symm_iv_len, symm_key_len) ){
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Capsule_change_policy() AES key not set" );
	}
	
	/* Open the plaintext file */
	policyFile = params[0].memref.buffer;
	res = TEE_SimpleOpen( policyFile, &policy_fd );
	if( policy_fd < 0 || res != TEE_SUCCESS ) {
		CHECK_SUCCESS(res, "TEE_SimpleOpen() cannot open %s", 
					  policyFile);
	}

	res = TEE_SimpleLseek( policy_fd, 0, TEE_DATA_SEEK_END, &pollen );

    if (res != TEE_SUCCESS)
        CHECK_GOTO(res, capsule_create_exit,
                    "TEE_SimpleLseek() could not seek.\nfd: %d, offset: %d, whence: %d\n",
                    policy_fd, 0, TEE_DATA_SEEK_END);

	res = TEE_SimpleLseek( policy_fd, 0, TEE_DATA_SEEK_SET, &temp );
    if (res != TEE_SUCCESS)
        CHECK_GOTO(res, capsule_create_exit,
                "TEE_SimpleLseek() could not seek.\nfd: %d, offset: %d, whence: %d\n",
                policy_fd, 0, TEE_DATA_SEEK_SET);
	//MSG( "Changing capsule %s policy with %s...", 
	//	 capsule_name, policyFile );

	/* Open the capsule file */
	res = TEE_SimpleOpen( capsule_name, &capsule_fd );
	if( capsule_fd < 0 || res != TEE_SUCCESS ) {
		CHECK_GOTO(res, capsule_create_exit,
				   "TEE_SimpleOpen() cannot open %s", capsule_name );
	}
	
	res = do_change_policy( policy_fd, capsule_fd, pollen );
	CHECK_GOTO( res, capsule_create_exit, "Do_change_policy() Error" );

capsule_create_exit:
	/* Close the fd */
	if( policy_fd > 0 ) 
		TEE_SimpleClose( policy_fd );
	if( capsule_fd > 0 )
		TEE_SimpleClose( capsule_fd );
	return res;
}

/* Create another trusted capsule from the currently opened
 * capsule */
TEE_Result capsule_create( uint32_t param_type, 
						   TEE_Param params[4] ) {
	
	TEE_Result 			res = TEE_SUCCESS;	
	int                 ptx_fd = -1, cap_fd = -1;
	char*               ptxFile;

	ASSERT_PARAM_TYPE( 
			TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,
			  				 TEE_PARAM_TYPE_NONE,
							 TEE_PARAM_TYPE_NONE,
							 TEE_PARAM_TYPE_NONE ) );
	
	/* Check if we are in a capsule session */
	if( capsule_name == NULL ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Capsule_create() no capsules opened" );
	}
	
	/* Check of a key was found to encrypt this capsule with */
	if( key_not_found(symm_iv, symm_id, symm_iv_len, symm_key_len) ){
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_SUCCESS( res, "Capsule_create() AES key not set" );
	}
	
	/* Open the plaintext file */
	ptxFile = params[0].memref.buffer;
	res = TEE_SimpleOpen( ptxFile, &ptx_fd );
	if( ptx_fd < 0 || res != TEE_SUCCESS) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		CHECK_SUCCESS(res, "TEE_SimpleOpen() cannot open %s", 
					  ptxFile);
	}
	//MSG( "Creating capsule %s...with %s", ptxFile, capsule_name );
	
	/* Open the capsule file */
	res = TEE_SimpleOpen( capsule_name, &cap_fd );
	if( cap_fd < 0 || res != TEE_SUCCESS) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		CHECK_GOTO(res, capsule_create_exit,
				   "TEE_SimpleOpen() cannot open %s", capsule_name );
	}
	
	res = do_create( ptx_fd, cap_fd );
	CHECK_GOTO( res, capsule_create_exit, "Do_create() Error" );	

capsule_create_exit:
	/* Close the fd */
	if( ptx_fd > 0 ) 
		TEE_SimpleClose( ptx_fd );
	if( cap_fd > 0 )
		TEE_SimpleClose( cap_fd );
	return res;
}

/* Reset all global variables that manage capsule state */
TEE_Result capsule_close(uint32_t param_type, TEE_Param params[4]) {

	TEE_Result res = TEE_SUCCESS;
	int        fd;

	if( capsule_name == NULL ) {
		res = TEE_ERROR_ITEM_NOT_FOUND; 			
		CHECK_SUCCESS( res, "No capsule was previously opened" );
	}

	UNUSED( params );
	
	ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE ) );
	//MSG( "Closing capsule %s for %d/%d", 
	//	  capsule_name, params[0].value.a, params[0].value.b );
	
	do_close( params[0].value.a, params[0].value.b );	
	
	res = TEE_SimpleOpen( capsule_name, &fd );
	if( fd < 0 || res != TEE_SUCCESS ) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		CHECK_SUCCESS(res, "TEE_SimpleOpen() cannot open %s", 
					  capsule_name);
	}
	res = do_run_policy( fd, Lstate, POLICY_FUNC, CLOSE_OP );
	CHECK_GOTO( res, capsule_close_exit, "do_run_policy() Error" );

capsule_close_exit:
	TEE_SimpleClose( fd );
	return res;
}

TEE_Result capsule_lseek( uint32_t param_type, 
				          TEE_Param params[4] ) {
	
	TEE_Result res = TEE_SUCCESS;
	int        pos;

	if( capsule_name == NULL ) {
		res = TEE_ERROR_ITEM_NOT_FOUND; 			
		CHECK_SUCCESS( res, "No capsule was previously opened" );
	}

	ASSERT_PARAM_TYPE( 
			TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
							 TEE_PARAM_TYPE_VALUE_INPUT,
							 TEE_PARAM_TYPE_VALUE_OUTPUT,
							 TEE_PARAM_TYPE_NONE ) );


	pos = do_lseek( params[0].value.a, params[0].value.b, 
			        params[1].value.a, params[1].value.b, true );
	//MSG( "Moved data cursor to %u for %d/%d", 
    //	  pos, params[0].value.a, params[0].value.b );
	
	if( pos >= 0 ) {
		params[2].value.a = pos - cap_head.data_begin ;
	} else {
		res = TEE_ERROR_NOT_SUPPORTED;
		params[2].value.a = pos;
	}
	return res;
}


TEE_Result capsule_pread( uint32_t param_type, TEE_Param params[4] ) {
	
	TEE_Result         res = TEE_SUCCESS;
	struct  		   cap_text_entry *cap_entry = NULL;
	int                fd;
	uint32_t           datapos_saved;
	bool               datapos_modified = false;
	
	if( capsule_name == NULL ) {
		res = TEE_ERROR_ITEM_NOT_FOUND; 			
		CHECK_SUCCESS( res, "No capsule was previously opened" );
	}
	
	ASSERT_PARAM_TYPE( 
		TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
						 TEE_PARAM_TYPE_VALUE_INPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_NONE ) );
	
	res = TEE_SimpleOpen( capsule_name, &fd );
	if( fd < 0 || res != TEE_SUCCESS ) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		CHECK_SUCCESS(res, "TEE_SimpleOpen() cannot open %s", 
					  capsule_name);
	}

	//MSG( "Preading %u B from %s for %d/%d at offset %d", 
	//	 params[2].memref.size, capsule_name, 
	//	 params[0].value.a, params[0].value.b, (int) params[1].value.a );

	/* Save current data pos */
	cap_entry = find_capsule_entry( &cap_head.proc_entries,
									params[0].value.a,
									params[0].value.b );
	if( cap_entry == NULL ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_GOTO( res, capsule_pread_exit, "Find_capusle_entry()"
				 	"-> tgid/fd %d/%d not found", 
					params[0].value.a, params[0].value.b );
	}

	datapos_modified = true;
	datapos_saved = cap_entry->data_pos;

	//MSG( "Saved data pos = %u, %u", datapos_saved, cap_entry->data_pos );

	/* Set new data pos based on params[1].value.a */
	do_lseek( params[0].value.a, params[0].value.b, 
			  params[1].value.a, START, true );

	curr_tgid = params[0].value.a;
	curr_fd = params[0].value.b;
	curr_len = params[2].memref.size;
	memset( curr_declassify_dest, 0, sizeof( curr_declassify_dest ) );
	
	res = do_run_policy( fd, Lstate, POLICY_FUNC, READ_OP );
	CHECK_GOTO( res, capsule_pread_exit, "do_run_policy() Error" );

	res = do_read( fd, params[0].value.a, params[0].value.b,
				   params[2].memref.buffer, &params[2].memref.size, 
				   true, true );
	CHECK_GOTO( res, capsule_pread_exit, "Do_read() Error" );

	res = lua_read_redact( Lstate, params[0].value.a, params[0].value.b,
						   params[2].memref.buffer, params[2].memref.size );
	CHECK_GOTO( res, capsule_pread_exit, "lua_read_redact() Error" );

capsule_pread_exit:
	/* Restore current data pos */
	if( datapos_modified ) cap_entry->data_pos = datapos_saved;
	//MSG( "restore data pos = %u, %u", datapos_saved, cap_entry->data_pos );
	TEE_SimpleClose( fd );
	return res;
}

TEE_Result capsule_read( uint32_t param_type, TEE_Param params[4] ) {
	
	TEE_Result         res = TEE_SUCCESS;
	int                fd;
	
	if( capsule_name == NULL ) {
		res = TEE_ERROR_ITEM_NOT_FOUND; 			
		CHECK_SUCCESS( res, "No capsule was previously opened" );
	}
	
	ASSERT_PARAM_TYPE( 
		TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE ) );
	
	res = TEE_SimpleOpen( capsule_name, &fd );
	if( fd < 0 || res != TEE_SUCCESS ) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		CHECK_SUCCESS(res, "TEE_SimpleOpen() cannot open %s", 
					  capsule_name);
	}

	//MSG( "Reading %u B from %s for %d/%d", 
	//	 params[1].memref.size, capsule_name, 
	//	 params[0].value.a, params[0].value.b );
	
	curr_tgid = params[0].value.a;
	curr_fd = params[0].value.b;
	curr_len = params[1].memref.size;
	memset( curr_declassify_dest, 0, sizeof( curr_declassify_dest ) );
	
	res = do_run_policy( fd, Lstate, POLICY_FUNC, READ_OP );
	CHECK_GOTO( res, capsule_read_exit, "do_run_policy() Error" );

	res = do_read( fd, params[0].value.a, params[0].value.b,
				       params[1].memref.buffer, &params[1].memref.size, 
				   true, true );
	CHECK_GOTO( res, capsule_read_exit, "Do_read() Error" );

	res = lua_read_redact( Lstate, params[0].value.a, params[0].value.b,
						   params[1].memref.buffer, params[1].memref.size );
	CHECK_GOTO( res, capsule_read_exit, "lua_read_redact() Error" );

capsule_read_exit:
	TEE_SimpleClose( fd );
	return res;
}

TEE_Result capsule_write( uint32_t param_type, TEE_Param params[4] ) {
	
	TEE_Result res = TEE_SUCCESS;
	int   	   fd;

	if( capsule_name == NULL ) {
		res = TEE_ERROR_ITEM_NOT_FOUND; 			
		CHECK_SUCCESS( res, "No capsule was previously opened" );
	}
	
	ASSERT_PARAM_TYPE( 
		TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
				         TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE ) 
	);
	
	res = TEE_SimpleOpen( capsule_name, &fd );
	if( fd < 0 || res != TEE_SUCCESS) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		CHECK_SUCCESS(res, "TEE_SimpleOpen() cannot open %s", 
					  capsule_name);
	}

	//MSG( "Writing %u B to %s from %d/%d", 
	//	 params[1].memref.size, capsule_name, 
	//	 params[0].value.a, params[0].value.b );

	curr_tgid = params[0].value.a;
	curr_fd = params[0].value.b;
	curr_len = params[1].memref.size;
	memset( curr_declassify_dest, 0, sizeof( curr_declassify_dest ) );
	
	res = do_run_policy( fd, Lstate, POLICY_FUNC, WRITE_OP );
	CHECK_GOTO( res, capsule_write_exit, "do_run_policy() Error" );
	
	res = do_write( fd, params[0].value.a, params[0].value.b,
					params[1].memref.buffer, &params[1].memref.size, 
					true, true );
	CHECK_GOTO( res, capsule_write_exit, "Do_write() Error" );

capsule_write_exit:
	TEE_SimpleClose( fd );
	return res;
}

TEE_Result capsule_ftruncate( uint32_t param_type, TEE_Param params[4] ) {
	
	TEE_Result res = TEE_SUCCESS;
	int        fd;

	if( capsule_name == NULL ) {
		res = TEE_ERROR_ITEM_NOT_FOUND; 			
		CHECK_SUCCESS( res, "No capsule was previously opened" );
	}
	
	ASSERT_PARAM_TYPE( 
		TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE ) 
	);
	
	res = TEE_SimpleOpen( capsule_name, &fd );
	if( fd < 0 || res != TEE_SUCCESS) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		CHECK_SUCCESS(res, "TEE_SimpleOpen() cannot open %s", 
					  capsule_name);
	}
	
	//MSG( "Calling ftruncate to %d B on %s", params[0].value.a );

	res = do_ftruncate( fd, params[0].value.a );
	CHECK_GOTO( res, capsule_ftruncate_exit, "Do_ftruncate() Error" );

capsule_ftruncate_exit:
	TEE_SimpleClose( fd );
	return res;
}

TEE_Result capsule_fstat( uint32_t param_type, TEE_Param params[4] ) {
	
	TEE_Result res = TEE_SUCCESS;

	if( capsule_name == NULL ) {
		res = TEE_ERROR_ITEM_NOT_FOUND; 			
		CHECK_SUCCESS( res, "No capsule was previously opened" );
	}
	
	ASSERT_PARAM_TYPE( 
		TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
				         TEE_PARAM_TYPE_VALUE_OUTPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE ) 
	);
	
	//MSG( "Calling fstat on %s from %d/%d", 
	//	  capsule_name, params[0].value.a, params[0].value.b );

	res = do_fstat( &params[1].value.a );
	CHECK_GOTO( res, capsule_write_exit, "Do_fstat() Error" );

capsule_write_exit:
	return res;
}

TEE_Result capsule_write_evaluate( uint32_t param_type, TEE_Param params[4] ) {

	TEE_Result res = TEE_SUCCESS;
	int        fd;

	if( capsule_name == NULL ) {
		res = TEE_ERROR_ITEM_NOT_FOUND; 			
		CHECK_SUCCESS( res, "No capsule was previously opened" );
	}
	
	ASSERT_PARAM_TYPE( 
		TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
				         TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE ) 
	);

	res = TEE_SimpleOpen( capsule_name, &fd );
	if( fd < 0 || res != TEE_SUCCESS ) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		CHECK_SUCCESS(res, "TEE_SimpleOpen() cannot open %s", 
					  capsule_name);
	}
	
	if( params[1].memref.size > sizeof( curr_declassify_dest ) )
		return TEE_ERROR_NOT_SUPPORTED;
	memcpy( curr_declassify_dest, params[1].memref.buffer,
			params[1].memref.size );

	//MSG( "Declassifying to dest %s having accessed %s from %d/%d", 
	//	 curr_declassify_dest, capsule_name, params[0].value.a, params[0].value.b );

	curr_tgid = params[0].value.a;
	curr_fd = params[0].value.b;
	curr_len = 0;

	
	res = do_run_policy( fd, Lstate, POLICY_FUNC, DECLASSIFY_OP );
	CHECK_GOTO( res, capsule_write_evaluate_exit,  "lua_run_policy() DECLASSIFY_OP error" );

capsule_write_evaluate_exit:
	TEE_SimpleClose( fd );
	return res;
}		
TEE_Result capsule_open_connection( uint32_t param_type, TEE_Param params[4] ) {
	TEE_Result res = TEE_SUCCESS;
	int        fd = -1;
	char       ip_addr[16];

	ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,
										TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_VALUE_OUTPUT,
										TEE_PARAM_TYPE_NONE ) );

	memcpy( ip_addr, params[0].memref.buffer, params[0].memref.size );

	res = do_open_connection( ip_addr, params[1].value.a, &fd );
	CHECK_SUCCESS( res, "Do_open_connection() Error" );
	
	params[2].value.a = fd;
	return res;
}

TEE_Result capsule_close_connection( uint32_t param_type, TEE_Param params[4] ) {
	TEE_Result res = TEE_SUCCESS;

	ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE ) );

	res = do_close_connection( params[0].value.a );
	CHECK_SUCCESS( res, "Do_close_connection() Error" );	
	
	return res;
}

TEE_Result capsule_recv_connection( uint32_t param_type, TEE_Param params[4] ) {
	TEE_Result res = TEE_SUCCESS;

	ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_MEMREF_OUTPUT,
										TEE_PARAM_TYPE_NONE, 
										TEE_PARAM_TYPE_NONE ) );
	
	res = do_recv_connection( params[0].value.a, params[1].memref.buffer, 
					          (int*) &params[1].memref.size );
	
	CHECK_SUCCESS( res, "Do_recv_connection() Error" );
	return res;
}

TEE_Result capsule_send_connection( uint32_t param_type, TEE_Param params[4] ) {
	TEE_Result res = TEE_SUCCESS;

	ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_MEMREF_INPUT,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE ) );

	res = do_send_connection( params[0].value.a, params[1].memref.buffer,
							  (int*) &params[1].memref.size );

	CHECK_SUCCESS( res, "Do_send_connection() Error" );

	return res;
}

TEE_Result capsule_send( uint32_t param_type, TEE_Param params[4] ) {	
	
	TEE_Result res = TEE_SUCCESS;

	ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_MEMREF_INPUT, 
									    TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_NONE ) );	
		
	res = do_send( params[0].value.a, params[1].memref.buffer, 
				   (int*) &params[1].memref.size, params[2].value.a,
				   params[2].value.b );
	CHECK_SUCCESS( res, "Do_send() Error" );
	
	return res;		
}	

TEE_Result capsule_recv_payload( uint32_t param_type, TEE_Param params[4] ) {	
	
	TEE_Result res = TEE_SUCCESS;

	ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_MEMREF_INPUT,
									    TEE_PARAM_TYPE_MEMREF_OUTPUT,
										TEE_PARAM_TYPE_NONE ) );	
		
	res = do_recv_payload( params[0].value.a, params[1].memref.buffer,
				           params[1].memref.size, params[2].memref.buffer,
					       params[2].memref.size );
	CHECK_SUCCESS( res, "Do_recv_payload() Error" );
	return res;		
}

TEE_Result capsule_recv_header( uint32_t param_type, TEE_Param params[4] ) {	
	
	TEE_Result  res = TEE_SUCCESS;
	AMessage   *msg;

	ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
									    TEE_PARAM_TYPE_MEMREF_OUTPUT,
									    TEE_PARAM_TYPE_VALUE_OUTPUT,
										TEE_PARAM_TYPE_VALUE_OUTPUT ) );	
		
	res = do_recv_header( params[0].value.a, &msg );
	CHECK_SUCCESS( res, "Do_recv_header() Error" );

	memcpy( params[1].memref.buffer, msg->hash.data, msg->hash.len );
	params[1].memref.size = msg->hash.len;
	params[2].value.a = msg->capsule_id;
	params[2].value.b = msg->op_code;
	params[3].value.a = msg->payload_len;
	params[3].value.b = msg->rvalue;

	free_hdr( msg );	
	return res;		
}	
