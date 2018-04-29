#ifndef FAKEOPTEE_H
#define FAKEOPTEE_H

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
