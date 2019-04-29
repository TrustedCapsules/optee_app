#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <tomcrypt.h>
#include <stdint.h>

#include <capsuleCommon.h>
#include <capsuleCrypt.h>

#include "entry.h"

uint32_t littleEndianToUint( const unsigned char *id ) {
	uint32_t int_id;
	int_id = ((uint32_t) *id & 0xff) | 
		( ((uint32_t) *(id+1) & 0xff) << 8 ) | 
		( ((uint32_t) *(id+2) & 0xff) << 16 ) | 
		( ((uint32_t) *(id+3) & 0xff) << 24 );
	return int_id;
}

bool compareHash( unsigned char* hash1, unsigned char* hash2, size_t lHash ) {
	for( int i = 0; i < lHash; i++ ) {
		if( hash1[i] != hash2[i] ) return false;
	}
	return true;
}

static void process_data( void *ptx, void *ctx, size_t len, capsuleEntry *e ) {
	process_ctr_aes( (const unsigned char *) ptx, (unsigned char *) ctx, len, 
					 e->key, e->keyLen, 0, e->iv, e->ivLen, &ctr_encrypt );
}

void encryptData( void* ptx, void *ctx, size_t len, capsuleEntry *e ) {
	process_data( ptx, ctx, len, e );
	return;
}

void decryptData( void* ctx, void *ptx, size_t len, capsuleEntry *e ) {
	process_data( ctx, ptx, len, e );
	return;
}

