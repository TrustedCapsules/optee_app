#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <aes_keys.h>
#include <capsule.h>
#include <capsule_util.h>
#include <amessage.pb-c.h>
#include "capsule_process.h"
#include "server_op.h"

/* Identifies the current capsule being used */

struct capsule_entry capsule_entry_map[NUM_CAPSULES] = {{ 0 }};
struct capsule_state state_map[NUM_CAPSULES*MAX_STATES_PER_CAPSULE];

/* Switch endianness of cap_id */
uint32_t change_endianness(unsigned char *id){
	uint32_t int_id;
	int_id = ((uint32_t) *id & 0xff) | 
		( ((uint32_t) *(id+1) & 0xff) << 8 ) | 
		( ((uint32_t) *(id+2) & 0xff) << 16 ) | 
		( ((uint32_t) *(id+3) & 0xff) << 24 );
	return int_id;
}



struct capsule_entry *get_curr_capsule( uint32_t cap_id ){
	
	int i;

	for (i = 0; i < NUM_CAPSULES; i++){
		if ( capsule_entry_map[i].id == cap_id){
			PRINT_INFO( "GET_CURRENT_CAPSULE(): found id 0x%08x\n", cap_id);
			return &(capsule_entry_map[i]);
		}
	}	
	return NULL;
}

int hash_data( const unsigned char* buffer, size_t buflen,
			   unsigned char* hash, size_t hashlen ) {
	
	hash_state md;

	/* We only support SHA256 for now */
	assert( hashlen == HASH_LEN );
	
	sha256_init( &md );
	sha256_process( &md, buffer, buflen );
	sha256_done( &md, hash );

	return 0;
}

static int process_data( void *ptx, void *ctx, size_t len,
			        struct capsule_entry *entry ){

	process_ctr_aes( (const unsigned char *) ptx, 
					 (unsigned char *) ctx, 
				 	 len, entry->key, entry->key_len, 
					 0, entry->iv, entry->iv_len, 
					 &ctr_encrypt );
	return 0;
}
int encrypt_data( void* ptx, void *ctx, size_t len, 
				  struct capsule_entry *entry ){
	return process_data( ptx, ctx, len, entry );
}

int decrypt_data( void* ctx, void *ptx, size_t len, 
				    struct capsule_entry *entry ){
	return process_data( ctx, ptx, len, entry );
}


int send_data( int fd, void *buf, size_t buf_len ) {
	int nw = 0, written = 0;
	do {
		nw = send( fd, ( (unsigned char*) buf ) + written, 
				   buf_len - written, 0 );
		if( nw <= 0 ) {
			PRINT_INFO( "SEND_DATA(): connection closed/aborted\n" );
			return nw;
		}

		written += nw;
	} while( written < buf_len && nw > 0 );

	return written;
}


int recv_data( int fd, void *buf, size_t buf_len ) {
	int nr, read = 0;
	do {
		nr = recv( fd, ( (unsigned char*) buf ) + read, 
				   buf_len - read, 0 );
		if( nr <= 0 ) {
			PRINT_INFO( "RECV_DATA(): connection closed/aborted\n" );
			return nr;	
		}
		read += nr;
	} while( read < buf_len && nr > 0 );

	return read;
}
