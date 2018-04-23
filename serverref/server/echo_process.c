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

void echo_simple_process( int fd ) {

	int  nr, nw;
	char buf[PACKET_SIZE];

	while(1) {
		nr = recv( fd, buf, PACKET_SIZE, 0 ); 	
		if( nr <= 0 ) {
			PRINT_INFO( "ECHO_SIMPLE_PROCESS(): "
						"connection broken/closed\n" );
			break;
		}
		PRINT_INFO( "ECHO_SIMPLE_PROCESS(): received "
					" %d B-> %s\n", nr, buf );

		nw = send_data( fd, buf, nr );
		if( nw <= 0 ) {
			PRINT_INFO( "ECHO_SIMPLE_PROCESS(): "
						"connection broken/closed\n" );
			break;
		}
		PRINT_INFO( "ECHO_SIMPLE_PROCESS(): sent"
					" %d B: %s\n", nw, buf );
	}

	PRINT_INFO( "ECHO_SIMPLE_PROCESS(): exiting connection...\n" );
}

void echo_enc_ser_process( int fd ) {

	int        nr, nw, i;
	unsigned char buf[PACKET_SIZE];
	unsigned char dbuf[PACKET_SIZE];
	char      *payload;
	int        payload_len;
	int        cap_id = -1;

	AMessage  *recv_hdr = NULL;

	while(1) {

		memset( buf, 0, PACKET_SIZE );
		/* We first receive the header for the data. We make
		 * the assumption that header < HEADER_SIZE */
		nr = recv_data( fd, buf, HEADER_SIZE );
		if( nr <= 0 ) {
			PRINT_INFO( "ECHO_ENC_SER_PROCESS(): "
						"recv_data() error\n" );
			break;
		}
	
		for( i = 0; i < NUM_CAPSULES; i++ ) {
			//PRINT_INFO( "ECHO_ENC_SER_PROCESS(): recv %d B"
			//			" %02x%02x%02x%02x %02x%02x%02x%02x\n", 
			//			nr, buf[0], buf[1], buf[2], buf[3],
			//	 		buf[48], buf[49], buf[50], buf[51] );

			PRINT_INFO( "ECHO_ENC_SER_PROCESS(): capsule_entry_map[%d]"
						" 0x%08x\n", i, capsule_entry_map[i].id );

			decrypt_data( buf, dbuf, nr, &capsule_entry_map[i] );

			//PRINT_INFO( "ECHO_ENC_SER_PROCESS(): decrypted %d B"
			//			" %02x%02x%02x%02x %02x%02x%02x%02x\n", 
			//			nr, dbuf[0], dbuf[1], dbuf[2], dbuf[3],
			//	 		dbuf[48], dbuf[49], dbuf[50], dbuf[51] );

			deserialize_hdr( &recv_hdr, dbuf, nr );
			if( recv_hdr == NULL ) {
				PRINT_INFO( "ECHO_ENC_SER_PROCESS(): deserialize_hdr()"
							" for capsule id 0x%08x failed\n", 
						 	capsule_entry_map[i].id );
				continue;
			}

			PRINT_INFO( "ECHO_ENC_SER_PROCESS(): recv_hdr->tz_id 0x%08x, "
						"capsule_entry_map[%d].id 0x%08x\n", 
						recv_hdr->capsule_id, i, capsule_entry_map[i].id );

			if( recv_hdr->capsule_id == (int) capsule_entry_map[i].id ) {
				PRINT_INFO( "ECHO_ENC_SER_PROCESS(): received header for"
							" capsule id 0x%08x\n", recv_hdr->tz_id );
				cap_id = i;
				break;
			}
		}

		if( cap_id == -1 ) {
			PRINT_INFO( "ECHO_ENC_SER_PROCESS(): no capsule found for "
						"this header\n" );
			break;
		}	

		PRINT_INFO( "ECHO_ENC_SER_PROCESS():\n"
					"capsule_id  0x%08x\n"
				    "op_code     %d\n"
					"tz_id       0x%08x\n"
					"rvalue      %d\n"
					"payload_len %d\n"
					"hash        ", recv_hdr->capsule_id, 
					recv_hdr->op_code, recv_hdr->tz_id, 
					recv_hdr->rvalue, recv_hdr->payload_len );
		for( i = 0; i < recv_hdr->hash.len; i++ ) {
			PRINT_INFO( "%02x", recv_hdr->hash.data[i] );
		}	
		PRINT_INFO( "\n" );

		/* We now know the payload size, so we can allocate a buffer 
		 * large enough for this purpose */
		payload = malloc( recv_hdr->payload_len );
		nr = recv_data( fd, payload, recv_hdr->payload_len );
		if( nr <= 0 ) {
			PRINT_INFO( "ECHO_ENC_SER_PROCESS(): "
						"recv_data() error\n" );
			free_hdr( recv_hdr);
			free( payload );
			break;
		}
	
		decrypt_data( payload, payload, nr, &capsule_entry_map[cap_id] );

		PRINT_INFO( "ECHO_ENC_SER_PROCESS(): received payload "
					"%d/%d B-> %s\n", nr, recv_hdr->payload_len,
				   	payload );

		/* We reserialize the header and send it back */ 
		serialize_hdr( recv_hdr->capsule_id, RESP_TEST, payload,
				   	   recv_hdr->payload_len, recv_hdr->rvalue, 
					   recv_hdr->tz_id, (uint8_t*) buf, 
					   HEADER_SIZE ); 

		PRINT_INFO( "ECHO_ENC_SER_PROCESS(): send "
					" %02x%02x%02x%02x %02x%02x%02x%02x\n", 
					buf[0], buf[1], buf[2], buf[3],
				 	buf[48], buf[49], buf[50], buf[51] );

		encrypt_data( buf, buf, HEADER_SIZE, &capsule_entry_map[cap_id] );

		nw = send_data( fd, buf, HEADER_SIZE );
		if( nw <= 0 ) {
			PRINT_INFO( "ECHO_ENC_SER_PROCESS(): "
						"connection broken/closed\n" );
			free_hdr( recv_hdr );
			free( payload );	
			return;
		}	

		/* We also send back the payload after */
		encrypt_data( payload, payload, recv_hdr->payload_len,
					  &capsule_entry_map[cap_id] );

		nw = send_data( fd, payload, recv_hdr->payload_len );
		if( nw <= 0 ) {
			PRINT_INFO( "ECHO_ENC_SER_PROCESS(): "
						"connection broken/closed\n" );
			free_hdr( recv_hdr );
			free( payload );	
			return;
		}		

		free_hdr( recv_hdr );
		recv_hdr = NULL;
		free( payload );
		payload = NULL;
	}

	if( recv_hdr != NULL ) free_hdr( recv_hdr );
	if( payload != NULL ) free( payload );
	PRINT_INFO( "ECHO_ENC_SER_PROCESS(): exiting connection...\n" );
	return;
}
