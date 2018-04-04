#ifndef CAPSULE_COMMAND_H
#define CAPSULE_COMMAND_H

/* Allocate shared memory with TrustZone */
TEEC_Result allocateSharedMem( TEEC_Context *ctx, 
                               TEEC_SharedMemory *mem );

TEEC_Result freeSharedMem( TEEC_SharedMemory *mem );

/* Initialize TrustZone Sessions */
TEEC_Result initializeContext( TEEC_Context *ctx );

TEEC_Result openSession( TEEC_Context *ctx, TEEC_Session *sess,
                         TEEC_UUID *uuid );

TEEC_Result closeSession( TEEC_Session *sess );

TEEC_Result finalizeContext( TEEC_Context *ctx );

/* AES Key Operation */
TEEC_Result register_aes_key( TEEC_Session *sess, unsigned char* id,
                              unsigned char* key, size_t keylen,
                              unsigned char* iv, size_t ivlen, 
                              uint32_t cSize, TEEC_SharedMemory *in );

/* State Operation */
TEEC_Result capsule_set_state( TEEC_Session *sess, TEEC_SharedMemory *in, 
                               char* key, uint32_t klen, char* val, 
                               uint32_t vlen, uint32_t id ); 

TEEC_Result capsule_get_state( TEEC_Session *sess, TEEC_SharedMemory *in, 
                               TEEC_SharedMemory *out, char* key, uint32_t klen, 
                               char* val, uint32_t vlen, uint32_t id ); 
/* Capsule Operation */
TEEC_Result capsule_open( TEEC_Session *sess, TEEC_SharedMemory *in, 
                          TEEC_SharedMemory *inout, char* filename, 
                          uint32_t name_len, char* contents, 
                          uint32_t file_len, char* decrypted_contents,
                          uint32_t *decrypted_len );

TEEC_Result capsule_close( TEEC_Session *sess, bool flush, char* contents,
                           uint32_t file_len, TEEC_SharedMemory *in, 
                           TEEC_SharedMemory *out, uint32_t *out_size,
                           char* new_contents );

/* Capsule network operations */
TEEC_Result capsule_open_connection( TEEC_Session *sess, TEEC_SharedMemory *in,
                                     char* ip_addr, uint32_t ip_addr_len, 
                                     int port, int *fd );

TEEC_Result capsule_read_connection( TEEC_Session *sess, TEEC_SharedMemory *in,
                                     char* buf, uint32_t blen, int fd, 
                                     int *nr );

TEEC_Result capsule_write_connection( TEEC_Session *sess, TEEC_SharedMemory *in, 
                                      char* buf, uint32_t blen, int fd, 
                                      int *nw );

TEEC_Result capsule_close_connection( TEEC_Session *sess, int fd );


TEEC_Result capsule_send( TEEC_Session *sess, TEEC_SharedMemory *in, 
                          char* buf, uint32_t blen, SERVER_OP s_op, int rv,
                          int fd, int* nw );
TEEC_Result capsule_recv_header( TEEC_Session *sess, TEEC_SharedMemory *out, 
                                 char* hash, uint32_t hlen, int* recv_plen,
                                 int* recv_id, int* recv_op, int* recv_rv, 
                                 int fd );
TEEC_Result capsule_recv_payload( TEEC_Session *sess, TEEC_SharedMemory *in, 
                                  TEEC_SharedMemory *out, char* buf, 
                                  uint32_t blen, char* hash, uint32_t hlen,
                                  int fd, int* nr );
#endif /* CAPSULE_COMMAND_H */
