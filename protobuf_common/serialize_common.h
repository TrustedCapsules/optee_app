#ifndef SERIALIZE_COMMON_H
#define SERIALIZE_COMMON_H


#ifdef TRUSTED_APP
	#define PRINT_MSG( fn, ... )  		 MSG( __VA_ARGS__ )
	#define MALLOC( size ) 		  		 TEE_Malloc( size, 0 )
	#define FREE( p )     		  		 TEE_Free( p )
#else 
	#define PRINT_MSG( fn, ... )  		 PRINT_INFO( fn __VA_ARGS__ ); \
										 PRINT_INFO( "\n" )
	#define MALLOC( size )        		 malloc( size )
	#define FREE( p )             		 free( p )
#endif

int serialize_hdr( uint32_t cap_id, uint32_t op_code,
					void* payload, size_t payload_len, int rv,
					int tz_id, uint8_t* msg_buf, size_t msg_len );

int deserialize_hdr( AMessage **msg, uint8_t* buf, size_t len );

void free_hdr( AMessage *msg );

#endif
