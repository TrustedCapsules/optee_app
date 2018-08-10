#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capsuleCommon.h>
#include <capsuleServerProtocol.h>
#include <capsuleKeys.h>
#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>
#include "network_helper.h"
#include "capsule_structures.h"
#include "capsule_helper.h"

TEE_Result serialize_hdr( uint32_t cap_id, SERVER_REQ req_code, size_t payload_len, char* device_id, size_t device_id_len, msgReqHeader* msg) {
	unsigned char hash[HASHLEN];
	int nonce;

	msg->capsuleID = cap_id;

	// TODO: add an error check for device_id_len < sizeof( msg.deviceID ))
	TEE_MemFill( msg->deviceID, 0, sizeof( msg->deviceID ) );
	TEE_MemMove( msg->deviceID, device_id, device_id_len );

	msg->req = req_code;
	TEE_GenerateRandom( &nonce, sizeof( nonce ) );
	msg->nonce = nonce;
	msg->payloadLen = payload_len;

	TEE_MemFill( hash, 0, HASHLEN );
	hash_data( (unsigned char*) msg, sizeof( msgReqHeader ), hash, sizeof( hash ) );
	TEE_MemMove( msg->hash, hash, sizeof( hash ) );

	return TEE_SUCCESS;
}

TEE_Result serialize_payload( int nonce, char* payload, size_t len, unsigned char* buf, size_t *buf_len ) {
	unsigned char hash[HASHLEN];
	msgPayload* p = (msgPayload*) TEE_Malloc( sizeof( msgPayload ) + len, 0 );
	
	p->nonce = nonce;
	TEE_MemMove( p->payload, payload, len);
	hash_data( (unsigned char*) p, sizeof( msgPayload ), hash, sizeof( hash ) );

	if (sizeof(msgPayload) + len > *buf_len) {
		return TEE_ERROR_SHORT_BUFFER;
	}

	TEE_MemMove(buf, p, sizeof(msgPayload) + len);

	*buf_len = sizeof(msgPayload) + len;

        TEE_Free(p);
	return TEE_SUCCESS;
}
