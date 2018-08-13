#ifndef NETWORK_HELPER_H
#define NETWORK_HELPER_H

TEE_Result serialize_hdr( uint32_t cap_id, SERVER_REQ req_code, size_t payload_len, char* device_id, size_t device_id_len, msgReqHeader* msg );

TEE_Result serialize_payload( int nonce, char* payload, size_t len, unsigned char* buf, size_t *buf_len );

#endif 
