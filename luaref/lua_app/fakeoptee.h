#ifndef FAKEOPTEE_H
#define FAKEOPTEE_H

#define UNUSED(x)		   (void)(x)

#define STATE_MAX_KEY_SIZE       128
#define STATE_MAX_VALUE_SIZE	 128

#define REPLACE_STR_MAX_SIZE	1024

#define READ_MAX_SIZE			2048

#define POLICY_MAX_SIZE 		4096
#define POLICY_COMMENT_SIZE 	 128
#define POLICY_BLACKLIST_SIZE  	 128
#define POLICY_STATE_SIZE        128
#define POLICY_IP_SIZE            16

#define POLICY_FUNC   			"evaluate_policy"
#define POLICY_RESULT 			"policy_result"
#define POLICY_LOG_OPEN 		"log_open"
#define POLICY_LOG_CLOSE 		"log_close"
#define POLICY_COMMENT          "comment"
#define POLICY_SERVER           "remote_server"
#define POLICY_VERSION          "policy_version"
#define POLICY_OP				"op"

#define POLICY_UPDATED_ERROR_MSG "updated"

typedef enum {
	POLICY_NIL,	

	// operation
	POLICY_OP_OPEN,
	POLICY_OP_CLOSE,
	
	// policy outcome
	POLICY_ALLOW,
	POLICY_NOT_ALLOW,
	POLICY_UPDATED,
	
	// return errors
	POLICY_ERROR_UNKNOWN_OP,
	POLICY_ERROR_LOC_NOT_AVAIL,
	POLICY_ERROR_TIME_NOT_AVAIL,
	POLICY_ERROR_SERVER_REPLY,
	POLICY_ERROR_SERVER_BROKEN_PIPE,
	POLICY_ERROR_KEY_NOT_FOUND,
	POLICY_ERROR_ACCESS_DENIED,
	POLICY_ERROR_DATA_CORRUPTED,
	POLICY_ERROR_UPDATE_FAILURE,
	POLICY_ERROR_REDACT_FAILURE,
	POLICY_ERROR_APPEND_BLACKLIST,
	POLICY_ERROR_REMOVE_BLACKLIST,
	
	// where
	POLICY_SECURE_STORAGE,
	POLICY_TRUSTED_APP,
	POLICY_CAPSULE_META,
	POLICY_REMOTE_SERVER,
	POLICY_LOCAL_DEVICE,
} POLICY_WORDS;

typedef enum {
	OPEN 	= POLICY_OP_OPEN,
	CLOSE 	= POLICY_OP_CLOSE,
} SYSCALL_OP;

typedef enum {
	WHERE_SECURE_STORAGE	= POLICY_SECURE_STORAGE,
	WHERE_TRUSTED_APP		= POLICY_TRUSTED_APP,
	WHERE_CAPSULE_META		= POLICY_CAPSULE_META,
	WHERE_REMOTE_SERVER		= POLICY_REMOTE_SERVER,
	WHERE_LOCAL_DEVICE		= POLICY_LOCAL_DEVICE,
} WHERE;

typedef enum {
	BL_TRUSTED_APP 			= POLICY_TRUSTED_APP,
	BL_SECURE_STORAGE 		= POLICY_SECURE_STORAGE,
	BL_CAPSULE_META 		= POLICY_CAPSULE_META,
} BLACKLIST;

typedef enum {
	NIL 										= POLICY_NIL,	
	
	ALLOW 										= POLICY_ALLOW,
	NOT_ALLOW 									= POLICY_NOT_ALLOW,
	UPDATED										= POLICY_UPDATED,

	// return errors
	ERROR_UNKNOWN_OP 							= POLICY_ERROR_UNKNOWN_OP,
	ERROR_LOC_NOT_AVAIL 						= POLICY_ERROR_LOC_NOT_AVAIL,
	ERROR_TIME_NOT_AVAIL 						= POLICY_ERROR_TIME_NOT_AVAIL,
	ERROR_SERVER_REPLY							= POLICY_ERROR_SERVER_REPLY,
	ERROR_SERVER_BROKEN_PIPE					= POLICY_ERROR_SERVER_BROKEN_PIPE,
	ERROR_KEY_NOT_FOUND 						= POLICY_ERROR_KEY_NOT_FOUND,
	ERROR_ACCESS_DENIED 						= POLICY_ERROR_ACCESS_DENIED,
	ERROR_DATA_CORRUPTED 						= POLICY_ERROR_DATA_CORRUPTED,
	ERROR_UPDATE_FAILURE						= POLICY_ERROR_UPDATE_FAILURE,
	ERROR_REDACT_FAILURE 						= POLICY_ERROR_REDACT_FAILURE,
	ERROR_APPEND_BLACKLIST						= POLICY_ERROR_APPEND_BLACKLIST,
	ERROR_REMOVE_BLACKLIST 						= POLICY_ERROR_REMOVE_BLACKLIST,
} RESULT;

typedef enum {
	false,
	true,
} bool;

typedef unsigned int uint32_t;

typedef enum {
	ORIGINAL,
	NEW,
} CAPSULE;

// TEE<->Lua API
RESULT 		TEE_getLocation( int* longitude, int* latitude, const WHERE w );
RESULT 		TEE_getTime( uint32_t* ts, const WHERE w );
RESULT 		TEE_getState( const char* key, size_t keyLen, 
				 		  char* value, size_t *valueLen, const WHERE w );
RESULT 		TEE_setState( const char* key, size_t keyLen, 
				   		  const char* value, size_t valueLen, const WHERE w );
RESULT 		TEE_deleteCapsule(void);
int 		TEE_capsuleLength( CAPSULE c );
RESULT 		TEE_appendToBlacklist( const char* str, size_t strLen, const WHERE w );
RESULT 		TEE_removeFromBlacklist( const char* str, size_t strLen, const WHERE w );
RESULT 		TEE_redact( const size_t start, const size_t end, 
				  	    const char* replaceStr, size_t len );
RESULT 		TEE_updatePolicy( lua_State *L );
int 		TEE_readCapsuleData( char** buf, size_t len, size_t offset, CAPSULE c );
SYSCALL_OP 	TEE_get_op();

// Testdriver dummy functions
extern RESULT (*dummy_location_fn)(int* longitude, int* latitude);

extern RESULT (*dummy_time_fn)(uint32_t* ts);

extern RESULT (*dummy_getState_fn)( const char* key, size_t keyLen, 
							 char* value, size_t* len );

extern RESULT (*dummy_setState_fn)( const char* key, size_t keyLen, 
							 const char* value, size_t valueLen );

extern void   (*dummy_deleteCapsule_fn)(void);

extern int (*dummy_capsuleLength_fn)(void);

extern RESULT (*dummy_appendBlacklist_fn)( const char* key, size_t strLen );

extern RESULT (*dummy_removeBlacklist_fn)( const char* key, size_t strLen );

extern RESULT (*dummy_redact_fn)( const size_t start, const size_t end, 
						const char* replaceStr, size_t len );

extern RESULT (*dummy_update_fn)( lua_State *L );

extern int (*dummy_readCapsuleData_fn)( char** buf, size_t len, size_t offset );

extern SYSCALL_OP op;

#endif
