#ifndef TEST_APP_H
#define TEST_APP_H

#define MAX_PATH 50

#define CHECK_EXIT( res, ... )             \
		if( (res) < 0 ) {                  \
			  PRINT_INFO( __VA_ARGS__ );   \
			  exit(-1);                    \
		}

#ifdef DEBUG
	#define DIAGNOSTIC(...) printf( __VA_ARGS__ )
#else
 	#define DIAGNOSTIC(...)
#endif

#define PRINT_INFO(...) printf( __VA_ARGS__ )
#define PRINT_ERR(...) fprintf( stderr, __VA_ARGS__ )

#define PRINT_CHARS( iter, size, buf )               \
	for( (iter) = 0; (iter) < (size); (iter)++ ) {   \
		PRINT_INFO( "%c", buf[(iter)] );     		 \
	}												 \
	PRINT_INFO( "\n" );

#define PRINT_HEX( iter, size, buf )                 \
	for( (iter) = 0; (iter) < (size); (iter)++ ) {   \
		PRINT_INFO( "%02x", buf[(iter)] );     		 \
	}												 \
	PRINT_INFO( "\n" );

#define CHECK_ERROR( res, ... )            \
		if( (res) < 0 ) {                  \
			  PRINT_INFO( __VA_ARGS__ );   \
			  return -1;                   \
		}	


#define COMPARE_TEXT( testnum, num, iter, ciph, plain, size )       \
		do {														\
			for( (iter) = 0; (iter) < (size); (iter)++ ) {			\
				if( ciph[(iter)] != plain[(iter)] ) {				\
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
					PRINT_INFO("%s: part #%d capsule text does not" \
					    " match the plaintext\n", testnum, num );		\
					return -1;                                      \
				}													\
			} 														\
		} while( 0 );												

#endif
