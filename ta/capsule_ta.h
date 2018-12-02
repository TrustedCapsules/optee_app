#ifndef CAPSULE_TA_H
#define CAPSULE_TA_H

// Not sure why these includes are required to compile while the others aren't
#include <capsuleBenchmark.h>
#include <capsulePolicy.h>

#define TZ_CRED          "cred"
#define TC_FILE_PARTS	 4
#define ASSERT_PARAM_TYPE( pt ) \
			do {                \
				if ( (pt) != param_type ) \
					return TEE_ERROR_BAD_PARAMETERS;  \
			} while( 0 )

/* AES key parameters */
	extern TEE_OperationHandle decrypt_op;
extern TEE_OperationHandle  encrypt_op;
extern TEE_OperationHandle  hash_op;
extern char                *capsule_name;
extern uint32_t 			symm_id;
extern uint8_t         	   *symm_iv;
extern uint32_t         	symm_iv_len;
extern uint32_t         	symm_key_len;
extern bool                 aes_key_setup;

/* Trusted Capsule file information */
extern struct capsule_text  cap_head;
extern SYSCALL_OP fuse_op; // open or close?

extern uint32_t 			temp_encrypted_len;
extern char 				*temp_encrypted;

/* Secure storage objects */
extern TEE_ObjectHandle keyFile;
extern char             keyID[];
//extern TEE_ObjectHandle stateFile; TODO: REMOVING THIS FOR NOW
extern uint32_t id_global_test_02;

/* Lua interpreter */
extern lua_State *Lstate;
extern int        curr_len;
//extern int        curr_cred; TODO: removing this for now.

/* Benchmarking */
extern struct benchmarking_ta timestamps[6];
extern int                    curr_ts;

#endif /* CAPSULE_TA_H */
