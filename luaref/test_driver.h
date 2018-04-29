#ifndef TEST_DRIVER_H
#define TEST_DRIVER

// get state
RESULT getState_Credential( const char* key, size_t keyLen, 
							char* value, size_t* valueLen );
RESULT getState_KeyError( const char* key, size_t keyLen, 
			    	   char* value, size_t* valueLen );
RESULT getState_ServerReplyError( const char* key, size_t keyLen, 
			    	   char* value, size_t* valueLen );
RESULT getState_ServerPipeError( const char* key, size_t keyLen, 
			    	   char* value, size_t* valueLen );
RESULT getState_AccessError( const char* key, size_t keyLen, 
			    	   char* value, size_t* valueLen );
RESULT getState_DataError( const char* key, size_t keyLen, 
			    	   char* value, size_t* valueLen );

// set state
RESULT setState_Credential( const char* key, size_t keyLen, 
							const char* value, size_t valueLen );
RESULT setState_ServerPipeError( const char* key, size_t keyLen, 
					   const char* value, size_t valueLen );
RESULT setState_ServerReplyError( const char* key, size_t keyLen, 
					   const char* value, size_t valueLen );
RESULT setState_AccessError( const char* key, size_t keyLen, 
					   const char* value, size_t valueLen );

// delete capsule
void deleteCapsule();

// update capsule
RESULT update_ServerReplyError( lua_State *L );
RESULT update_ServerPipeError( lua_State *L );
RESULT update_DataError( lua_State *L );
RESULT update_FailError( lua_State *L );
RESULT update_None( lua_State *L );
RESULT update( lua_State *L );

// get location
RESULT location_incorrect( int* longitude, int* latitude );
RESULT location_correct( int* longitude, int* latitude );
RESULT location_NoService( int* longitude, int* latitude );

// get time
RESULT time_incorrect( uint32_t* ts );
RESULT time_correct( uint32_t* ts );
RESULT time_NoService( uint32_t* ts );

// redact
RESULT redact( const size_t start, const size_t end, 
			   const char* replStr, size_t len );
RESULT redact_failure( const size_t start, const size_t end, 
					   const char* replStr, size_t len );

// append/remove from blacklist
RESULT appendToBlacklist( const char* key, size_t len );
RESULT appendToBlacklist_failure( const char* key, size_t len );
RESULT removeFromBlacklist( const char* key, size_t len );
RESULT removeFromBlacklist_failure( const char* key, size_t len );

// file
int capsuleLength();
int capsuleLength_error();
int readCapsuleData( char** buf, size_t len, size_t offset );
int readCapsuleData_error( char** buf, size_t len, size_t offset );

#endif
