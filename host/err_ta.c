#include <tee_client_api.h>
#include <tee_api_types.h>
#include "err_ta.h"

#define SOCKET_CREATE_FAIL 			1234554320
#define SOCKET_OPEN_CONNECTION_FAIL 1234554321
#define SOCKET_READ_FAIL			1234554322
#define SOCKET_WRITE_FAIL			1234554323
#define SOCKET_CLOSE_CONNECTION_FAIL		1234554324
#define SOCKET_CLOSE_ALL_CONNECTIONS_FAIL	1234554325

TEEC_Result check_result( TEEC_Result res, char* fn, uint32_t orig ) {
	
	if( res != TEEC_SUCCESS ) { 									
		fprintf( stderr, "%s(): ", fn );						
		switch( res ) {                 							
			case TEEC_ERROR_GENERIC:    							
				fprintf( stderr, "TEEC_ERROR_GENERIC" );			
				break;
			case TEE_ERROR_CORRUPT_OBJECT:
				fprintf( stderr, "TEEC_ERROR_CORRUPT_OBJECT" );
				break;				
			case TEEC_ERROR_ACCESS_DENIED: 							
				fprintf( stderr, "TEEC_ERROR_GENERIC" );            
				break;												
			case TEEC_ERROR_CANCEL:									
				fprintf( stderr, "TEEC_ERROR_CANCEL" );				
			break;												
			case TEEC_ERROR_ACCESS_CONFLICT:						
				fprintf( stderr, "TEEC_ERROR_ACCESS_CONFLICT" );	
			break;												
			case TEEC_ERROR_EXCESS_DATA:							
				fprintf( stderr, "TEEC_ERROR_EXCESS_DATA" );		
				break;												
			case TEEC_ERROR_BAD_FORMAT:								
				fprintf( stderr, "TEEC_ERROR_BAD_FORMAT" );			
				break;												
			case TEEC_ERROR_BAD_PARAMETERS:							
				fprintf( stderr, "TEEC_ERROR_BAD_PARAMETERS" );		
				break;												
			case TEEC_ERROR_BAD_STATE:								
				fprintf( stderr, "TEEC_ERROR_BAD_STATE" );			
				break;												
			case TEEC_ERROR_ITEM_NOT_FOUND:							
				fprintf( stderr, "TEEC_ERROR_ITEM_NOT_FOUND" );     
				break;  											
			case TEEC_ERROR_NOT_IMPLEMENTED: 						
				fprintf( stderr, "TEEC_ERROR_NOT_IMPLEMENTED" );    
				break;												
			case TEEC_ERROR_NOT_SUPPORTED:							
				fprintf( stderr, "TEEC_ERROR_NOT_SUPPORTED" );		
				break;												
			case TEEC_ERROR_NO_DATA:								
				fprintf( stderr, "TEEC_ERROR_NO_DATA" );			
				break;												
			case TEEC_ERROR_OUT_OF_MEMORY:							
				fprintf( stderr, "TEEC_ERROR_OUT_OF_MEMORY" );		
				break;												
			case TEEC_ERROR_BUSY:									
				fprintf( stderr, "TEEC_ERROR_BUSY" );				
				break;												
			case TEEC_ERROR_COMMUNICATION:							
				fprintf( stderr, "TEEC_ERROR_COMMUNICATION" );		
				break;												
			case TEEC_ERROR_SECURITY:								
				fprintf( stderr, "TEEC_ERROR_SECURITY" );			
				break;												
			case TEEC_ERROR_SHORT_BUFFER:							
				fprintf( stderr, "TEEC_ERROR_SHORT_BUFFER" );		
				break;												
			case TEEC_ERROR_EXTERNAL_CANCEL:						
				fprintf( stderr, "TEEC_ERROR_EXTERNAL_CANCEL" );	
				break;												
			case TEEC_ERROR_TARGET_DEAD:							
				fprintf( stderr, "TEEC_ERROR_TARGET_DEAD" );		
				break;				
			case TEEC_ERROR_POLICY_ERROR:
				fprintf( stderr, "TEEC_ERROR_POLICY_ERROR" );
				break;
			default:												
				break;												
		}
	
		if( orig != 0 ) {
			switch( orig ) {
			case TEEC_ORIGIN_API:
				fprintf( stderr, " Origin: TEEC_ORIGIN_API" );
				break;
			case TEEC_ORIGIN_COMMS:
				fprintf( stderr, " Origin: TEEC_ORIGIN_COMMS" );
				break;
			case TEEC_ORIGIN_TEE:
				fprintf( stderr, " Origin: TEEC_ORIGIN_TEE" );
				break;
			case TEEC_ORIGIN_TRUSTED_APP:
				fprintf( stderr, " Origin: TEEC_ORIGIN_TRUSTED_APP" );
				break;
			default:
				break;
			}
		}

		fprintf( stderr, "\n" );
	}

	return res;
}
