#define STR_TRACE_USER_TA "TRUSTED_CAPSULE_TA"

#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>
#include <tee_api.h>
#include <string.h>
#include <capsule.h>
#include <amessage.pb-c.h>
#include <lua.h>
#include "capsule_structures.h"
#include "capsule_ta.h"
#include "capsule_commands.h"
#include "capsule_helper.h"
#include "capsule_op.h"

/* UNUSED - RSA key parameters */
TEE_ObjectHandle curr_pub = TEE_HANDLE_NULL;
TEE_ObjectHandle curr_priv = TEE_HANDLE_NULL;

/* AES key parameters */
TEE_OperationHandle	    decrypt_op;
TEE_OperationHandle     encrypt_op;
TEE_OperationHandle     hash_op;
char			       *capsule_name = NULL;
uint32_t 		        symm_id = 0;
uint8_t                *symm_iv = NULL;
uint32_t                symm_iv_len = 0;
uint32_t		        symm_key_len = 0;
uint32_t                symm_chunk_size = 0;
bool                    aes_key_setup = false;

struct HashList         hash_head;

/* Trusted Capsule file index information */
struct capsule_text     cap_head;

/* Secure Storage Objects -> keys */
TEE_ObjectHandle keyFile = TEE_HANDLE_NULL;
char             keyID[] = "aes_key_file";

/* Secure Storage Objects -> credentials, persistent state */
TEE_ObjectHandle stateFile = TEE_HANDLE_NULL;

/* Interpreter State - this is messy, and will only work if policy
 *                     evaluation is synchronous. */
lua_State *Lstate = NULL;
int        curr_tgid = 0;
int        curr_fd = 0;
int        curr_len = 0;
char       curr_declassify_dest[128];
int        curr_cred = 0;

/* Opens persistent files for reading/writing when
 * new session is created*/
TEE_Result TA_CreateEntryPoint(void) {
	
	TEE_Result res = TEE_SUCCESS;
	DMSG( "Trusted Capsule Application started..." );

	if( keyFile != TEE_HANDLE_NULL ) {
		TEE_Panic( 0 );
	}	
	
	/* This is a hack to get the keys into the TEE. We run
	 * capsule_test from host/ which will register the keys 
	 * into the TEE's secure storage and run a bunch of 
	 * sanity tests 
	 *
	 * This should be moved to open() later as part of
	 * key register and find functions.
	 *
	 * */	

	res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE,
									keyID, sizeof( keyID ),
									TEE_DATA_FLAG_SHARE_READ | 
									TEE_DATA_FLAG_SHARE_WRITE |
									TEE_DATA_FLAG_ACCESS_READ |
									TEE_DATA_FLAG_ACCESS_WRITE,
									&keyFile );

	if( res == TEE_ERROR_ITEM_NOT_FOUND ) {
		MSG( "First activation...creating key file..." );
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
										 keyID, sizeof( keyID ),
		 TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_SHARE_WRITE |
		 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
										  0, NULL, 0, &keyFile );
		CHECK_SUCCESS( res, "TEE_CreatePersistentObject() Error" );
		MSG( "Key file created" );
	} else {
		CHECK_SUCCESS( res, "TEE_OpenPersistentObject() Error" );
	}
	
	return res;
}

void TA_DestroyEntryPoint(void) {
	//MSG( "Destroyed Trusted Capsule context\n" );
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_type,
		TEE_Param params[4], void **sess_ctx) {

	UNUSED( sess_ctx );
	UNUSED( params );
	UNUSED( param_type );

	//MSG( "New Session Created..." );	
	LIST_INIT( &hash_head );
	LIST_INIT( &cap_head.proc_entries );

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
	UNUSED( sess_ctx );

	//MSG( "Closing Trusted Capsule %s session", capsule_name );
	
	TEE_FreeTransientObject( curr_priv );
	TEE_FreeTransientObject( curr_pub );

	TEE_CloseObject( keyFile );
	TEE_CloseObject( stateFile );

	free_hashlist( &hash_head );
	free_caplist( &cap_head.proc_entries );

	if( capsule_name != NULL ) {
		TEE_Free( capsule_name );
	}

	if( symm_iv != NULL ) {
		TEE_FreeOperation( decrypt_op );
		TEE_FreeOperation( encrypt_op );
		TEE_FreeOperation( hash_op );

		TEE_Free( symm_iv );
	}

	lua_close_context( &Lstate );

	//MSG( "Successfully closed trusted capsule %s session", capsule_name );
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, 
				                      uint32_t cmd_id,
		                              uint32_t param_type, 
									  TEE_Param params[4]) {
	
	UNUSED( sess_ctx );

	//unsigned long long val;
	//val = read_cntpct();
	//MSG( "Invoke: %llu", val );
		
	switch (cmd_id) {
	case CAPSULE_REGISTER_RSA_KEY:
		return register_rsa_key(param_type, params);
	case CAPSULE_REGISTER_AES_KEY:
		return register_aes_key(param_type, params);
	case CAPSULE_SET_STATE:
		return set_state(param_type, params);
	case CAPSULE_GET_STATE:
		return get_state(param_type, params);
	case CAPSULE_OPEN:
		return capsule_open(param_type, params);			
	case CAPSULE_CREATE:
		return capsule_create(param_type, params);
	case CAPSULE_CHANGE_POLICY:
		return capsule_change_policy(param_type, params);
	case CAPSULE_CLOSE:
		return capsule_close(param_type, params);
	case CAPSULE_LSEEK:
		return capsule_lseek(param_type, params);
	case CAPSULE_PREAD:
		return capsule_pread(param_type, params);
	case CAPSULE_READ:
		return capsule_read(param_type, params);
	case CAPSULE_WRITE:
		return capsule_write(param_type, params);
	case CAPSULE_FTRUNCATE:
		return capsule_ftruncate(param_type, params);
	case CAPSULE_FSTAT:
		return capsule_fstat(param_type,params);
	case CAPSULE_WRITE_EVALUATE:
		return capsule_write_evaluate(param_type, params);
	case CAPSULE_OPEN_CONNECTION:
		return capsule_open_connection(param_type, params);
	case CAPSULE_CLOSE_CONNECTION:
		return capsule_close_connection(param_type, params);
	case CAPSULE_RECV_CONNECTION:
		return capsule_recv_connection(param_type, params);
	case CAPSULE_SEND_CONNECTION:
		return capsule_send_connection(param_type, params);
	case CAPSULE_SEND:
		return capsule_send(param_type, params);
	case CAPSULE_RECV_HEADER:
		return capsule_recv_header(param_type, params);
	case CAPSULE_RECV_PAYLOAD:
		return capsule_recv_payload(param_type, params);
		
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

