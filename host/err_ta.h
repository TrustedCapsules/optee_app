#ifndef ERR_TA_H
#define ERR_TA_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <tee_client_api.h>
#include <capsuleCommon.h>

#define PRINT_INFO(...) printf( __VA_ARGS__ )
#define PRINT_LOOP( it, start, end, buf ) 			  \
		for( (it) = (start); (it) < (end); (it)++ ) { \
			PRINT_INFO( "%c", buf[(it)] ); 			  \
		} 											  \
		PRINT_INFO( "\n" );
#define PRINT_ERR(...) fprintf( stderr, __VA_ARGS__ )                   

#define CHECK_RESULT( res, ... ) do { 	  				\
			if( ( res ) != TEEC_SUCCESS ) {  			\
				PRINT_INFO( __VA_ARGS__ );  			\
				PRINT_INFO( "\n" );                     \
				return (res);							\
			}							 				\
		} while( 0 );

#define COMPARE_TEXT( testnum, num, iter, ciph, plain, size )       \
		do {														\
			for( (iter) = 0; (iter) < (size); (iter)++ ) {			\
				if( ciph[(iter)] != plain[(iter)] ) {				\
					PRINT_INFO( "Mismatch at %d\n", (iter) );       \
					PRINT_INFO( "nr: %d, ciphtext: ", (size) );		\
					for( (iter) = 0; (iter) < (size); (iter)++ ) {	\
						PRINT_INFO( "%c", ciph[(iter)] );			\
					}												\
					PRINT_INFO("\n");								\
					PRINT_INFO( "nr: %d, plaintext: ", (size) );	\
					for( (iter) = 0; (iter) < (size); (iter)++ ) {	\
						PRINT_INFO( "%c", plain[(iter)] );			\
					}												\
					PRINT_INFO("\n");								\
					CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,		\
						"test_%02d: part #%d capsule text does not"	\
					    " match the plaintext", testnum, num );		\
				}													\
			} 														\
		} while( 0 );												

#define COMPARE_CAPSULE( testnum, num, iter, cap1, cap2 , size )    \
		do {														\
			for( (iter) = 0; (iter) < (size); (iter)++ ) {			\
				if( cap1[(iter)] != cap2[(iter)] ) {				\
					PRINT_INFO( "Mismatch at %d\n", (iter) );       \
					PRINT_INFO( "nr: %d, original: ", (size) );		\
					for( (iter) = 0; (iter) < (size); (iter)++ ) {	\
						PRINT_INFO( "%02x", cap1[(iter)] );			\
					}												\
					PRINT_INFO("\n");								\
					PRINT_INFO( "nr: %d, created: ", (size) );		\
					for( (iter) = 0; (iter) < (size); (iter)++ ) {	\
						PRINT_INFO( "%02x", cap2[(iter)] );			\
					}												\
					PRINT_INFO("\n");								\
					CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,		\
						"test_%02d: part #%d the two capsules are"	\
					    " not the same", testnum, num );			\
				}													\
			} 														\
		} while( 0 );												

#define COMPARE_LEN( testnum, num, len1, len2 ) 					\
		do {														\
			if( (len1) != (len2) ) {								\
				CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,			\
					"test_%02d: part #%d the two buffers are not"	\
					" the same length( " #len1 "=%d, "              \
					#len2 "=%d )", testnum,	num, len1, len2 );		\
			}														\
		} while( 0 );


TEEC_Result check_result( TEEC_Result res, char* fn, uint32_t orig );

#endif /* ERR_TA_H */
