#ifndef CAPSULE_TA_H
#define CAPSULE_TA_H

// Not sure why these includes are required to compile while the others aren't
#include <capsuleBenchmark.h>
#include <capsulePolicy.h>

#define TZ_CRED          "cred"

#define ASSERT_PARAM_TYPE( pt ) \
			do {                \
				if ( (pt) != param_type ) \
					return TEE_ERROR_BAD_PARAMETERS;  \
			} while( 0 )	

/* AES key parameters */
extern TEE_OperationHandle  decrypt_op;
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

/* Secure storage objects */
extern TEE_ObjectHandle keyFile;                                   
extern char             keyID[];
extern TEE_ObjectHandle stateFile;
extern TEE_ObjectHandle deviceFile;

/* Capsule object metadata hashtable */
extern kv_pair cap_metadata;

/* Lua interpreter */
extern lua_State *Lstate;
extern int        curr_len;
extern int        curr_cred;

/* Benchmarking */
extern struct benchmarking_ta timestamps[6];
extern int                    curr_ts;

#endif /* CAPSULE_TA_H */
