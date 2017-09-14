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


/* Randomly fill out the state_map for capsules that we will
 * test with the get_state policy */
void register_state(void) {
	state_map[0].id = change_endianness(capsule_data_array[13].id);
	strcpy( state_map[0].key, "still_employed" );
	strcpy( state_map[0].val, "true" );

	state_map[1].id = change_endianness(capsule_data_array[19].id);
	strcpy( state_map[1].key, "current_doctor" );
	strcpy( state_map[1].val, "1ade" );

	state_map[2].id = change_endianness(capsule_data_array[19].id);
	strcpy( state_map[2].key, "current_insurer" );
	strcpy( state_map[2].val, "1ade" );
	
	state_map[3].id = change_endianness(capsule_data_array[21].id);
	strcpy( state_map[3].key, "current_doctor" );
	strcpy( state_map[3].val, "1ade" );

	state_map[4].id = change_endianness(capsule_data_array[21].id);
	strcpy( state_map[4].key, "current_insurer" );
	strcpy( state_map[4].val, "1ade" );

	state_map[5].id = change_endianness(capsule_data_array[35].id);
	strcpy( state_map[5].key, "allowed_to_view" );
	strcpy( state_map[5].val, "true" ); // Change to false to test

	state_map[6].id = change_endianness(capsule_data_array[32].id);
	strcpy( state_map[6].key, "current_doctor" );
	strcpy( state_map[6].val, "doc1" ); // Change to doc2 to test

	state_map[7].id = change_endianness(capsule_data_array[32].id);
	strcpy( state_map[7].key, "current_insurer" );
	strcpy( state_map[7].val, "ins1" ); // Change to insu2 to test
}

/* Retrieve capsule info from aes_keys.h and store them in 
 * capsule_entry
 */
void register_capsule_entry(void){
	
	int		i;

	for( i = 0; i < sizeof( capsule_data_array ) / 
					sizeof( struct capsule_data ); i++ ) {
	
		capsule_entry_map[i].key = key_std;
		capsule_entry_map[i].id = change_endianness(capsule_data_array[i].id);
		capsule_entry_map[i].iv = iv_std;
		capsule_entry_map[i].chunk_size = capsule_data_array[i].chunk_size;	
		capsule_entry_map[i].key_len = sizeof(key_std); 
		capsule_entry_map[i].iv_len = sizeof(iv_std);
		capsule_entry_map[i].version = 1;
		
		if( strcmp( (const char*) capsule_data_array[i].str,
					"policychange" ) == 0 || 
		    strcmp( (const char*) capsule_data_array[i].str,
				    "test_imgl_needtoknow_4KB" ) == 0 ||
		 	strcmp( (const char*) capsule_data_array[i].str,
				 	"test_1M_needtoknow_1KB" ) == 0 ) {
			capsule_entry_map[i].reply = &reply_change_policy;
			capsule_entry_map[i].version = 2;
		} else if ( strcmp( (const char*) capsule_data_array[i].str,
					"remotedelete" ) == 0 ) {
			capsule_entry_map[i].reply = &reply_delete;
		} else if ( strcmp( (const char*) capsule_data_array[i].str,
					"remotestate" ) == 0 || 
					strcmp( (const char*) capsule_data_array[i].str,
					"test_html_patient_1KB" ) == 0 || 
				 	strcmp( (const char*) capsule_data_array[i].str,
					"test_1M_patient_1KB" ) == 0 ||
					strcmp( (const char*) capsule_data_array[i].str,
					"test_bio_ehrpatient_4KB" ) == 0 ||
					strcmp ( (const char*) capsule_data_array[i].str,
					"test_imgsm_private_4KB" ) == 0 ) {
			capsule_entry_map[i].reply = &reply_get_state;
		} else if ( strcmp( (const char*) capsule_data_array[i].str,
					"reportlocid" ) == 0 ||
				    strcmp( (const char*) capsule_data_array[i].str,
					"test_imgs_audit_1KB" ) == 0 ||
					strcmp( (const char*) capsule_data_array[i].str,
					"test_1M_audit_1KB" ) == 0 ||
					strcmp( (const char*) capsule_data_array[i].str,
					"test_faketranscript_identity_4KB" ) == 0 ) {
			// TODO: EHR can't have two replies? Need to fix?
			capsule_entry_map[i].reply = &reply_report_locid;
		} else {
			capsule_entry_map[i].reply = &reply_echo;
		}

		PRINT_INFO( "REGISTER_CAPSULE_TO_KEY_ENTRY(): id 0x%08x,"
		        	" chunk_size %d, key_len %d, iv_len %d\n", 
		       		capsule_entry_map[i].id, capsule_entry_map[i].chunk_size,
		       		capsule_entry_map[i].key_len, capsule_entry_map[i].iv_len );
	}
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
