#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <capsule_util.h>
#include <aes_keys.h>
#include <capsule.h>
#include <amessage.pb-c.h>
#include <serialize_common.h>
#include "server_op.h"

extern int policy_state;

int reply_change_policy( int fd, int id, AMessage *hdr, char* payload ) {

	FILE 	 *fp;
	int   	  paylen = 0, nr = 0, nw;
	char 	 *policy = NULL;
	uint8_t   buf[PACKET_SIZE];

	//printf( "policy_state: %d\n", policy_state );
	unsigned int version = *(unsigned int*) (void*) payload;
	
//	if( version != capsule_entry_map[id].version ) {
	if( policy_state % 4 == 0 ) {
		fp = fopen( REPLACEMENT_POLICY_EVAL, "r" );
		fseek( fp, 0, SEEK_END );
		paylen = ftell(fp);
		fseek( fp, 0, SEEK_SET );
		policy = malloc( paylen );
		nr = fread( policy, sizeof(char), paylen, fp );
		if ( nr != paylen ) {
			free(policy);
			policy = NULL;
			paylen = 0;
		}
		printf( "changing to new policy\n" );
	} else if( policy_state % 2 == 0 ) {
		fp = fopen( ORIGINAL_POLICY_EVAL, "r" );
		fseek( fp, 0, SEEK_END );
		paylen = ftell(fp);
		fseek( fp, 0, SEEK_SET );
		policy = malloc( paylen );
		nr = fread( policy, sizeof(char), paylen, fp );
		if ( nr != paylen ) {
			free(policy);
			policy = NULL;
			paylen = 0;
		}
		printf( "changing to old policy\n" );
	} else {
		printf( "no policy change\n" );
	}
	
	serialize_hdr( hdr->capsule_id, RESP_POLICY_CHANGE, policy,
				   paylen, hdr->rvalue, hdr->tz_id, buf, HEADER_SIZE );

	encrypt_data( buf, buf, HEADER_SIZE, &capsule_entry_map[id] );

	nw = send_data( fd, buf, HEADER_SIZE );
	if( nw <= 0 ) {
		free( policy );	
		return -1;
	}

	if( paylen > 0 ) {
		encrypt_data( policy, policy, paylen, &capsule_entry_map[id] );
		nw = send_data( fd, policy, paylen );
		if( nw <= 0 ) {
			free( policy );
			return -1;
		}
	}

	free( policy );
	return 0;
}

int reply_get_state( int fd, int id, AMessage *hdr, char* payload ) {

	uint8_t buf[PACKET_SIZE];
	int nw, i, paylen = 0;

	for( i = 0; i < sizeof(state_map)/sizeof(struct capsule_state); i++ ) {
		PRINT_INFO( "state_map[i].id: 0x%08x, hdr->capsule_id: 0x%08x"
					" state_map[i].key: %s, hdr->key: %s\n",
					state_map[i].id, hdr->capsule_id, state_map[i].key,
					payload );
		// TODO: Will this affect the remote state?
		if( state_map[i].id == hdr->capsule_id ) {// &&
			// strcmp( state_map[i].key, payload ) == 0 ) {
			paylen = strlen( state_map[i].val );	
			break;
		}
	}

	serialize_hdr( hdr->capsule_id, RESP_STATE, state_map[i].val,
				   paylen, hdr->rvalue, hdr->tz_id,
				   buf, HEADER_SIZE );
	
	encrypt_data( buf, buf, HEADER_SIZE, &capsule_entry_map[id] );

	nw = send_data( fd, buf, HEADER_SIZE );
	if( nw <= 0 ) return -1;
	
	if( paylen > 0 ) {	
		encrypt_data( state_map[i].val, buf, paylen, 
					  &capsule_entry_map[id] );
	
		nw = send_data( fd, buf, paylen );
		if( nw <= 0 ) return -1;
	}
	
	return 0;
}

int reply_report_locid( int fd, int id, AMessage *hdr, char* payload ) {
	
	uint8_t buf[PACKET_SIZE];
	int     nw;
	int    *val = (int*)(void*) payload;

	serialize_hdr( hdr->capsule_id, RESP_SEND_ACK, NULL, 0, hdr->rvalue,
				   hdr->tz_id, buf, HEADER_SIZE ); 

	PRINT_INFO( "longitude: %d\nlatitude: %d\n"
				"cred: 0x%08x\ntime: %d\nop: %d\n"
				"len: %d\noffset: %d\n", val[0], val[1], 
				val[2], val[3], val[4], val[5], val[6] );
	
	encrypt_data( buf, buf, HEADER_SIZE, &capsule_entry_map[id] );
	nw = send_data( fd, buf, HEADER_SIZE );
	if( nw <= 0 ) {
		PRINT_INFO( "Send data returned with %d\n", nw );
		return -1;
	}
	
	return 0;
}

int reply_delete( int fd, int id, AMessage *hdr, char* payload ) {

	uint8_t buf[PACKET_SIZE];
	int     nw;

	serialize_hdr( hdr->capsule_id, RESP_DELETE, NULL, 0, hdr->rvalue,
				   hdr->tz_id, buf, HEADER_SIZE ); 

	encrypt_data( buf, buf, HEADER_SIZE, &capsule_entry_map[id] );
	
	PRINT_INFO( "Reply delete 0x%08x\n", hdr->capsule_id );

	nw = send_data( fd, buf, HEADER_SIZE );
	if( nw <= 0 ) return -1;

	return 0;
}

int reply_echo( int fd, int id, AMessage *hdr, char* payload ) {

	uint8_t buf[PACKET_SIZE];
	int nw;

	serialize_hdr( hdr->capsule_id, RESP_TEST, payload,
				   hdr->payload_len, hdr->rvalue, hdr->tz_id,
				   buf, HEADER_SIZE );
	
	encrypt_data( buf, buf, HEADER_SIZE, &capsule_entry_map[id] );

	nw = send_data( fd, buf, HEADER_SIZE );
	if( nw <= 0 ) return -1;
		
	encrypt_data( payload, payload, hdr->payload_len, 
				  &capsule_entry_map[id] );
	
	nw = send_data( fd, payload, hdr->payload_len );
	if( nw <= 0 ) return -1;

	return 0;
}

void capsule_process( int fd ) {

	int           nr, i;
	unsigned char buf[PACKET_SIZE];
	unsigned char dbuf[PACKET_SIZE];
	int           cap_id = -1;
	
	char         *payload;
	AMessage     *recv_hdr = NULL;

	while(1) {
		nr = recv_data( fd, buf, HEADER_SIZE );
		if( nr <= 0 ) {
			PRINT_INFO( "CAPSULE_PROCESS(): connection closed\n" );
			break;
		}

		// PRINT_INFO( "Received %d B ( HEADER %d B )\n", nr, HEADER_SIZE );

		for( i = 0; i < NUM_CAPSULES; i++ ) {
			decrypt_data( buf, dbuf, nr, &capsule_entry_map[i] );
			deserialize_hdr( &recv_hdr, dbuf, nr );
			if( recv_hdr == NULL ) {
				PRINT_INFO( "CAPSULE_PROCESS(): deserialize_hdr()"
							" for capsule id 0x%08x failed\n",
							capsule_entry_map[i].id );
				continue;

			}
				
			if( recv_hdr->capsule_id == (int) capsule_entry_map[i].id ) {
				cap_id = i;
				break;
			}
		}

		if( cap_id < 0 ) {
			PRINT_INFO( "CAPSULE_PROCESS(): capsule not found\n" );
			break;
		}

		PRINT_INFO( "CAPSULE_PROCESS(): id 0x%08x found\n",
					recv_hdr->capsule_id );
		
		payload = malloc( recv_hdr->payload_len );
		nr = recv_data( fd, payload, recv_hdr->payload_len );
		if( nr <= 0 ) {
			break;
		}

		decrypt_data( payload, payload, nr, &capsule_entry_map[cap_id] );

		int* temp = (int*)(void*) payload;

		PRINT_INFO( "payload: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n", temp[0], temp[1], temp[2], temp[3], temp[4], temp[5], temp[6] );
		if( capsule_entry_map[cap_id].reply( fd, cap_id, recv_hdr, payload) ) break; 
	
		free_hdr( recv_hdr );
		recv_hdr = NULL;
		free( payload );
		payload = NULL;
	}

	if( recv_hdr != NULL ) free_hdr( recv_hdr );
	if( payload != NULL ) free( payload );
	PRINT_INFO( "CAPSULE_PROCESS(): closing connection\n" );
	return;
}
	
