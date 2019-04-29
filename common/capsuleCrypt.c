#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tomcrypt.h>

#include "capsuleCommon.h"
#include "capsuleCrypt.h"
#include "capsuleKeys.h"

// process_ctr_aes processes an AES encryption/decryption operation.
// It is modified AES encryption/decryption which allows mid-block 
// encryption/decryption if the correct counter is supplied.
void process_ctr_aes(const unsigned char *in, unsigned char *out,
                    size_t len, unsigned char *key, size_t keylen,
                    unsigned int counter, unsigned char* iv, 
                    unsigned int iv_len, process_func func) {
    symmetric_CTR ctr;
    unsigned int  decoded_len = 0;
    unsigned int  decrypt_len = 0;
    unsigned char in_sec[256];
    unsigned char out_sec[256];
    int           index = 15;   

    CHECK_CRYPT_OK(register_cipher(&aes_desc), "register_cipher");
    CHECK_CRYPT_OK(ctr_start(find_cipher("aes"), iv, key, keylen, 
                             0, CTR_COUNTER_BIG_ENDIAN, &ctr),
                             "ctr_start" );
    counter = counter/16;
    while( counter != 0 ) {
        ctr.ctr[index] = counter % 256;
        counter = counter / 256;
        index--;
    }
    cipher_descriptor[ctr.cipher].ecb_encrypt(ctr.ctr, 
                                              ctr.pad, 
                                              &ctr.key);

    while( decoded_len < len ) {
        if( len - decoded_len >= 256 )
            decrypt_len = 256;
        else
            decrypt_len = len - decoded_len;
		/*
     	printf("%d %d %d %02x%02x%02x %02x%02x%02x\n",
                   ctr.padlen, ctr.blocklen, ctr.ctrlen, 
                   ctr.ctr[13], ctr.ctr[14], ctr.ctr[15], 
                   ctr.pad[127], ctr.pad[15], ctr.pad[0] );
		*/

        memcpy( in_sec, in+decoded_len, decrypt_len );
        CHECK_CRYPT_OK( func(in_sec, out_sec, decrypt_len, &ctr), 
                        "<<process_func>>" );
        memcpy( out+decoded_len, out_sec, decrypt_len ); 
        decoded_len += 256;
    }

    CHECK_CRYPT_OK( ctr_done(&ctr), "ctr_done" );
    CHECK_CRYPT_OK( unregister_cipher(&aes_desc), 
                    "unregister_cipher" );

    /* Clear memory */
    zeromem(&ctr, sizeof(ctr));
}

void hashData( void* buf, size_t lBuf, unsigned char* hash, size_t lHash ) {
	hash_state md;

	/* We only support SHA256 for now */
	/*
	printf( "hashData(): buf %zu (B)\n", lBuf );
	printf( "hashData(): got - %zu expected - %d\n", lHash, HASHLEN );
	printf( "hashData(): buf\n\t" );
	char *p = buf;
	for( int i = 0; i < lBuf; i++ ) {
		printf( "%02x", p[i] );
	}
	printf( "\n" );
	*/	

	assert( lHash == HASHLEN );
	
	sha256_init( &md );
	sha256_process( &md, (const unsigned char*) buf, lBuf );
	sha256_done( &md, hash );
}

