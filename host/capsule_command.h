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

/* UNUSED */
TEEC_Result register_rsa_key( TEEC_Session *sess, TEEC_SharedMemory *in,
							  uint8_t* modulus, size_t mlen, 
				              uint8_t* pub_exp, size_t publen,
							  uint8_t* priv_exp, size_t prlen,
							  uint8_t* prime1, size_t p1len, 
							  uint8_t* prime2, size_t p2len, 
							  uint8_t* exp1, size_t exp1len,
							  uint8_t* exp2, size_t exp2len,
							  uint8_t* coeff, size_t colen );
TEEC_Result capsule_rsa_decrypt();
TEEC_Result capsule_rsa_encrypt();

/* AES Key Operation */
TEEC_Result register_aes_key( TEEC_Session *sess, unsigned char* id,
				              unsigned char* key, size_t keylen,
							  unsigned char* iv, size_t ivlen, 
							  uint32_t cSize, TEEC_SharedMemory *in );

/* State Operation */
TEEC_Result capsule_set_state( TEEC_Session *sess, TEEC_SharedMemory *in, 
				               char* key, uint32_t klen, char* val, uint32_t vlen, 
			                   uint32_t id ); 
TEEC_Result capsule_get_state( TEEC_Session *sess, TEEC_SharedMemory *in, 
							   TEEC_SharedMemory *out, char* key, uint32_t klen, 
							   char* val, uint32_t vlen, uint32_t id ); 
/* Capsule Operation */
TEEC_Result capsule_change_policy( TEEC_Session *sess, 
								   TEEC_SharedMemory *in,
				            	   char* filename, uint32_t flen );
TEEC_Result capsule_create( TEEC_Session *sess, TEEC_SharedMemory *in,
				            char* filename, uint32_t flen );
TEEC_Result capsule_open( TEEC_Session *sess, TEEC_SharedMemory *in,
						  char* filename, uint32_t flen, int pid, int fd );

TEEC_Result capsule_ftruncate( TEEC_Session *sess, uint32_t size ); 
TEEC_Result capsule_read( TEEC_Session *sess, TEEC_SharedMemory *out,
				 		  char* buf, uint32_t len, uint32_t *nr, int pid,
			              int fd );
TEEC_Result capsule_write( TEEC_Session *sess, TEEC_SharedMemory *in,
						   char* buf, uint32_t len, uint32_t *nw, int pid,
			   			   int fd );
TEEC_Result capsule_lseek( TEEC_Session *sess, uint32_t offset, 
				           FILE_POS flag, uint32_t* pos, int pid, 
						   int fd );
TEEC_Result capsule_fstat( TEEC_Session *sess, int pid, 
						   int fd, uint32_t* data_size );
TEEC_Result capsule_close( TEEC_Session *sess, int pid, int fd );

TEEC_Result capsule_open_connection( TEEC_Session *sess, TEEC_SharedMemory *in,
									 char* ip_addr, uint32_t ip_addr_len, int port,
									 int *fd );

TEEC_Result capsule_read_connection( TEEC_Session *sess, TEEC_SharedMemory *in,
									 char* buf, uint32_t blen, int fd, int *nr );

TEEC_Result capsule_write_connection( TEEC_Session *sess, TEEC_SharedMemory *in, 
									  char* buf, uint32_t blen, int fd, int *nw );

TEEC_Result capsule_close_connection( TEEC_Session *sess, int fd );


TEEC_Result capsule_send( TEEC_Session *sess, TEEC_SharedMemory *in, 
				          char* buf, uint32_t blen, SERVER_OP s_op, int rv,
			   			  int fd, int* nw );
TEEC_Result capsule_recv_header( TEEC_Session *sess, TEEC_SharedMemory *out, 
								 char* hash, uint32_t hlen, int* recv_plen,
			   					 int* recv_id, int* recv_op, int* recv_rv, int fd );
TEEC_Result capsule_recv_payload( TEEC_Session *sess, TEEC_SharedMemory *in, 
								  TEEC_SharedMemory *out, char* buf, 
								  uint32_t blen, char* hash, uint32_t hlen,
			  					  int fd, int* nr );
TEEC_Result capsule_collect_benchmark( TEEC_Session *sess );
TEEC_Result capsule_clear_benchmark( TEEC_Session *sess );
#endif /* CAPSULE_COMMAND_H */
