#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>
 
#include "fakeoptee.h"
#include "hash.h"

capsuleTable* capsules = NULL;

size_t append_file( const char* filename, char *buf, size_t len ) {

}

size_t open_file( const char* filename, char *buf, size_t len ) {
	FILE    *fp;
	size_t   sz;
	
	fp = fopen( filename, "r+" );
	if( fp == NULL ) {
		printf( "Could not read file %s\n", filename );
		return 0;
	}

	fseek( fp, 0L, SEEK_END );
	sz = ftell( fp );
	if( sz > len ) {
		printf( "Buffer size too small, need %zu (B), got %zu (B)\n", sz, len );
		return 0;
	}

	memset( buf, 0, len );
	fseek( fp, 0L, SEEK_SET );
	sz = fread( buf, sizeof(char), sz, fp );

	fclose( fp );
	return sz;	
}

uint32_t littleEndianToUint( const unsigned char *id ) {
	uint32_t int_id;
	int_id = ((uint32_t) *id & 0xff) | 
		( ((uint32_t) *(id+1) & 0xff) << 8 ) | 
		( ((uint32_t) *(id+2) & 0xff) << 16 ) | 
		( ((uint32_t) *(id+3) & 0xff) << 24 );
	return int_id;
}

void registerStates( capsuleEntry *e, char* buf, size_t len ) {
	
	char* lineStart = buf;	
	char* lineEnd = strchr( buf, '\n' );		

	while( lineEnd != NULL && lineEnd - buf <= len ) {
		char* keyStart = lineStart;
		char* keyEnd = strchr( lineStart, ':' );
		if( keyEnd == NULL ) {
				printf( "registerCapsules: state manifest file for capsule %s"
						" has incorrect format\n", e->name );
				break;
		}
		char* valStart = keyEnd + 1;
		char* valEnd = lineEnd;
		
		stateEntry* se = newStateEntry( keyStart, keyEnd - keyStart, 
										valStart, valEnd - valStart );

		stateInsert( e->stateMap, keyStart, keyEnd - keyStart, se );
		printf( "\tAdd key: %s val: %s\n", se->key, se->value );

		lineStart = lineEnd + 1;	
		lineEnd = strchr( lineStart, '\n' );
	}

}

void registerCapsules(void){
	capsules = newCapsuleTable( 10 );
	
	int numCapsules = sizeof( manifest ) / sizeof( capsuleManifestEntry );
	for( int i = 0; i < numCapsules; i++ ) {
		uint32_t id = littleEndianToUint( manifest[i].id );
		capsuleEntry* ce = newCapsuleEntry( id, manifest[i].name, 
											sizeof( manifest[i].name ) );
		capsuleInsert( capsules, id, ce );
		
		printf( "Capsule %s (0x%x): \n", manifest[i].name, id ); 

		char stateFile[255] = {0};
		char states[1024] = {0};
		memcpy( stateFile, "../server_capsules/", 19 );
		strcat( stateFile, manifest[i].name );
		strcat( stateFile, ".state" );	
		size_t len = open_file( stateFile, states, sizeof(states ) );
		if( len > 0 ) 
			registerStates( ce , states, len );	
	} 
}

void hashData( void* buf, size_t lBuf, unsigned char* hash, size_t lHash ) {
	hash_state md;

	/* We only support SHA256 for now */
	assert( lHash == HASHLEN );
	
	sha256_init( &md );
	sha256_process( &md, (const unsigned char*) buf, lBuf );
	sha256_done( &md, hash );
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

int encryptData( void* ptx, void *ctx, size_t len, capsuleEntry *e ) {
	return process_data( ptx, ctx, len, e );
}

int decryptData( void* ctx, void *ptx, size_t len, capsuleEntry *e ) {
	return process_data( ctx, ptx, len, e );
}

int sendData( int fd, void *buf, size_t len ) {
	int nw = 0, written = 0;
	do {
		nw = send( fd, ( (unsigned char*) buf ) + written, len - written, 0 );
		if( nw <= 0 ) {
			fprintf( stderr, "sendData(): connection closed or aborted, wrote %s" 
							 " before connection closed\n", buf );
			return nw;
		}

		written += nw;
	} while( written < len && nw > 0 );

	return written;
}


int recvData( int fd, void *buf, size_t len ) {
	int nr, read = 0;
	do {
		nr = recv( fd, ( (unsigned char*) buf ) + read, len - read, 0 );
		if( nr <= 0 ) {
			fprintf( stderr, "recvData(): connection closed or aborted, read %s"
							 " before connection closed\n", buf );
			return nr;	
		}
		read += nr;
	} while( read < len && nr > 0 );

	return read;
}

