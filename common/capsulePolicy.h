#ifndef CAPSULE_POLICY_H
#define CAPSULE_POLICY_H

#define POLICY_STATE_MAX_KEY_SIZE       128
#define POLICY_STATE_MAX_VALUE_SIZE	 	128

#define POLICY_REPLACE_STR_MAX_SIZE		1024

#define POLICY_READ_MAX_SIZE			2048

#define POLICY_MAX_SIZE 				4096
#define POLICY_COMMENT_SIZE 	 		128
#define POLICY_BLACKLIST_SIZE  	 		128	
#define POLICY_STATE_SIZE        		128
#define POLICY_IP_SIZE            		16

#define POLICY_FUNC   			"policy"
#define POLICY_RESULT 			"policy_result"
#define POLICY_LOG_OPEN 		"log_open"
#define POLICY_LOG_CLOSE 		"log_close"
#define POLICY_COMMENT          "comment"
#define POLICY_SERVER           "remote_server"
#define POLICY_VERSION          "policy_version"
#define POLICY_OP				"op"

typedef enum
{
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
	POLICY_ERROR_KEY_BAD_SIZE,
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
	OPEN_OP 	= POLICY_OP_OPEN,
	CLOSE_OP 	= POLICY_OP_CLOSE,
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
	ERROR_KEY_BAD_SIZE							= POLICY_ERROR_KEY_BAD_SIZE,
	ERROR_ACCESS_DENIED 						= POLICY_ERROR_ACCESS_DENIED,
	ERROR_DATA_CORRUPTED 						= POLICY_ERROR_DATA_CORRUPTED,
	ERROR_UPDATE_FAILURE						= POLICY_ERROR_UPDATE_FAILURE,
	ERROR_REDACT_FAILURE 						= POLICY_ERROR_REDACT_FAILURE,
	ERROR_APPEND_BLACKLIST						= POLICY_ERROR_APPEND_BLACKLIST,
	ERROR_REMOVE_BLACKLIST 						= POLICY_ERROR_REMOVE_BLACKLIST,
} RESULT;

typedef enum {
	ORIGINAL,
	NEW,
} CAPSULE;

#define POLICY_UPDATED_ERROR_MSG		"update"

#endif
