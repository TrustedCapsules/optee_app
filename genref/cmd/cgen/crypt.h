#ifndef CRYPT_H
#define CRYPT_H

#define CHECK_CRYPT_OK( err, name ) do { 					\
	if ((err != CRYPT_OK )) { 								\
		printf( "%s: %s\n", name, error_to_string( err ) );	\
	}														\
} while(0)

typedef int (*process_func) ( const unsigned char *in, unsigned char *out,
							unsigned long len, symmetric_CTR *ctr );

void process_ctr_aes( const unsigned char* in, unsigned char* out,
					size_t len, unsigned char* key, size_t keylen,
					unsigned int counter, unsigned char* iv,
					unsigned int iv_len, process_func func );

void hashData( void* buf, size_t lBuf, unsigned char* hash, size_t lHash );

#endif
