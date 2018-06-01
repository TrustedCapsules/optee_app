#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capsuleCommon.h>

#include "amessage.pb-c.h"
#include "serialize_common.h"

#ifdef TRUSTED_APP
#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>
#include <lua.h>
#include "capsule_structures.h"
#include "capsule_helper.h"
#else
#include <aes_keys.h>
#include <capsule_util.h>
#include <server_op.h>
#endif


int serialize_hdr( uint32_t cap_id, SERVER_OP op_code, 
			    void* payload, size_t payload_len, int rv,
				int tz_id, uint8_t* msg_buf, size_t msg_len ) {

	AMessage 		msg = AMESSAGE__INIT;
	unsigned char   hash[HASH_LEN];
	uint32_t        msg_size;

	if( payload_len <= 0 ) {
		memset( hash, 0, HASH_LEN );
	} else {
		hash_data( payload, payload_len, hash, HASH_LEN ); 
	}

	msg.capsule_id = cap_id;
	msg.op_code = op_code;  
	msg.hash.data = hash;
	msg.hash.len = HASH_LEN;
	msg.payload_len = payload_len; 
	msg.rvalue = rv;
	msg.tz_id = tz_id;

	msg_size = amessage__get_packed_size( &msg );
	*(uint32_t*)(void*)msg_buf = msg_size;
	
	//PRINT_MSG( "SERIALIZE_HDR(): ", "hdr size is %u B", msg_size );
	if( msg_size > msg_len - sizeof(size_t) ) {
		PRINT_MSG( "SERIALIZE_HDR(): ", "buf size %zd B is too small", 
				   msg_len );
		return -1;
	}

	return amessage__pack( &msg, msg_buf + sizeof(uint32_t) );
}

int deserialize_hdr( AMessage **msg, uint8_t* buf, size_t len ) {

	uint32_t  msg_len;
	
	if( len != HEADER_SIZE ) {	
		PRINT_MSG( "DESERIALIZE_HDR() ", "buffer must be %u B not %u B", 
				   HEADER_SIZE, len );
		return -1;
	}

	msg_len = *(uint32_t*)(void*) buf;
	//PRINT_MSG( "DESERIALIZE_HDR() ", "hdr size is %u (0x%08x) B", 
	//			msg_len, msg_len );
	/* Unpack the packet */
	*msg = amessage__unpack( NULL, msg_len, buf + sizeof(uint32_t) );   
	if ( *msg == NULL ) {
		PRINT_MSG( "DESERIALIZE(): ", "amessage__unpack() failed" );
		return -1;
	}

	return 0;
}

/* Frees the protobuf header */
void free_hdr( AMessage *msg ) {
	amessage__free_unpacked( msg, NULL );
}

