#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <capsule.h>
#include "err_ta.h"
#include "key_data.h"


TEEC_Result allocateSharedMem( TEEC_Context *ctx, 
						       TEEC_SharedMemory* mem ) {
	TEEC_Result res;
	res = TEEC_AllocateSharedMemory( ctx, mem );
	return check_result( res, "TEEC_AllocateSharedMemory", 0 );
}

TEEC_Result freeSharedMem( TEEC_SharedMemory* mem ) {
	TEEC_ReleaseSharedMemory( mem );
	return TEEC_SUCCESS;
}

/* UNUSED - Registers an (RSA-key pair, keyword) with the Trusted World
 * for encrypt and decrypt operation
 */

TEEC_Result register_rsa_key( TEEC_Session *sess, TEEC_SharedMemory *in,
							  uint8_t* modulus, size_t mlen,
				              uint8_t* pub_exp, size_t publen,
							  uint8_t* priv_exp, size_t prlen,
							  uint8_t* prime1, size_t p1len,
							  uint8_t* prime2, size_t p2len, 
							  uint8_t* exp1, size_t exp1len,
							  uint8_t* exp2, size_t exp2len,
							  uint8_t* coeff, size_t colen ) {
	TEEC_Result    res;
	TEEC_Operation op;
	uint32_t       ret_orig;
	struct rsa_key private_key;
	TEE_Attribute  key_attrs[8];
	
	/* Load the RSA key at ../../capsule_gen/keys/private_key.der.
	 * See key_data.h to see how we cheat */

	private_key.modulus = modulus;
	private_key.modulus_len = mlen;
	private_key.pub_exp = pub_exp;
	private_key.pub_exp_len = publen;
	private_key.priv_exp = priv_exp;
	private_key.priv_exp_len = prlen;
	private_key.prime1 = prime1;
	private_key.prime1_len = p1len;
	private_key.prime2 = prime2;
	private_key.prime2_len = p2len;
	private_key.exp1 = exp1;
	private_key.exp1_len = exp1len;
	private_key.exp2 = exp2;
	private_key.exp2_len = exp2len;
	private_key.coeff = coeff;
	private_key.coeff_len = colen;

	/* Serialize the RSA key into shared memory buffer
	 */

	add_attr( 0, key_attrs, TEE_ATTR_RSA_MODULUS, 
			  private_key.modulus, private_key.modulus_len );
	add_attr( 1, key_attrs, TEE_ATTR_RSA_PUBLIC_EXPONENT, 
			  private_key.pub_exp, private_key.pub_exp_len );

	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( in->buffer, 0, in->size ); 
	create_rsa_key( &op, private_key.modulus_len * 8, 
			    	TEE_TYPE_RSA_PUBLIC_KEY, key_attrs, 2, 
			        in );
	res = TEEC_InvokeCommand( sess, CAPSULE_REGISTER_RSA_KEY, 
					          &op, &ret_orig );
	
	check_result( res, "TEEC_InvokeCommand->CAPSULE_REGISTER_RSA_KEY",
			      ret_orig );
	
	add_attr( 2, key_attrs, TEE_ATTR_RSA_PRIVATE_EXPONENT, 
			  private_key.priv_exp, private_key.priv_exp_len );
	add_attr( 3, key_attrs, TEE_ATTR_RSA_PRIME1, 
			  private_key.prime1, private_key.prime1_len );
	add_attr( 4, key_attrs, TEE_ATTR_RSA_PRIME2, 
			  private_key.prime2, private_key.prime2_len );
	add_attr( 5, key_attrs, TEE_ATTR_RSA_EXPONENT1, 
			  private_key.exp1, private_key.exp1_len );
	add_attr( 6, key_attrs, TEE_ATTR_RSA_EXPONENT2, 
			  private_key.exp2, private_key.exp2_len );
	add_attr( 7, key_attrs, TEE_ATTR_RSA_COEFFICIENT, 
			  private_key.coeff, private_key.coeff_len );

	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( in->buffer, 0, in->size ); 
	create_rsa_key( &op, private_key.modulus_len * 8, 
			    	TEE_TYPE_RSA_KEYPAIR, key_attrs, 8, 
				    in );
	
	res = TEEC_InvokeCommand( sess, CAPSULE_REGISTER_RSA_KEY, 
					          &op, &ret_orig );
	return check_result( res, 
				 "TEEC_InvokeCommand->CAPSULE_REGISTER_RSA_KEY",
				 ret_orig );
}

/* UNUSED */
TEEC_Result capsule_rsa_decrypt() {
	return TEEC_SUCCESS;
}
TEEC_Result capsule_rsa_encrypt() {
	return TEEC_SUCCESS;
}

/* Registers an (AES-key pair, keyword) with the Trusted World
 * for encrypt and decrypt operation.
 */

TEEC_Result register_aes_key( TEEC_Session *sess, unsigned char *id,
							  unsigned char *key, size_t keylen, 
							  unsigned char *iv, size_t ivlen, 
							  uint32_t cSize, TEEC_SharedMemory *in ) {
	TEEC_Result    res;
	TEEC_Operation op;
	uint32_t       ret_orig;
	TEE_Attribute  key_attr;

	/* We bootstrap the short story capsules */

	key_attr.attributeID = TEE_ATTR_SECRET_VALUE;
	key_attr.content.ref.buffer = (void*) key;
	key_attr.content.ref.length = keylen;

	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( in->buffer, 0, in->size ); 
	create_aes_key( &op, key_attr.content.ref.length * 8, 
					TEE_TYPE_AES, id, &key_attr, 1, iv, ivlen, 
					in,	cSize ); 
	res = TEEC_InvokeCommand( sess, CAPSULE_REGISTER_AES_KEY, &op, 
					          &ret_orig );
	
	return check_result( res, 
				"TEEC_InvokeCommand->CAPSULE_REGISTER_AES_KEY", 
		   		 ret_orig );
}

/* Test command to get a state in the TA. 
 */
TEEC_Result capsule_get_state( TEEC_Session *sess, TEEC_SharedMemory *in, 
							   TEEC_SharedMemory *out, char* key, uint32_t klen, 
							   char* val, uint32_t vlen, uint32_t id ) {
	uint32_t 	   ret_orig;
	TEEC_Operation op;
	TEEC_Result    res;
	
	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( in->buffer, 0, in->size );
	memset( out->buffer, 0, out->size );

	memcpy( in->buffer, key, klen );

	op.paramTypes = TEEC_PARAM_TYPES( TEEC_MEMREF_PARTIAL_INPUT,
									  TEEC_MEMREF_PARTIAL_OUTPUT,
									  TEEC_VALUE_INPUT,
									  TEEC_NONE );
	
	op.params[0].memref.parent = in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = klen;
	op.params[1].memref.parent = out;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = vlen;
	op.params[2].value.a = id;
	
	res = TEEC_InvokeCommand( sess, CAPSULE_GET_STATE, &op, &ret_orig );
	if( res == TEE_SUCCESS ) {
		memcpy( val, out->buffer, vlen );
	}

	return check_result( res, "TEEC_InvokeCommand->CAPSULE_GET_STATE", 
					     ret_orig );
}

/* Test command to set a state in the TA. 
 */
TEEC_Result capsule_set_state( TEEC_Session *sess, TEEC_SharedMemory *in, 
				               char* key, uint32_t klen, char* val, 
							   uint32_t vlen, uint32_t id ) {
	uint32_t 	   ret_orig;
	TEEC_Operation op;
	TEEC_Result    res;
	
	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( in->buffer, 0, in->size );

	memcpy( in->buffer, key, klen );

	op.paramTypes = TEEC_PARAM_TYPES( TEEC_MEMREF_PARTIAL_INPUT,
									  TEEC_MEMREF_TEMP_INPUT,
									  TEEC_VALUE_INPUT,
									  TEEC_NONE );
	
	op.params[0].memref.parent = in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = klen;
	op.params[1].tmpref.buffer = (void*) val;
	op.params[1].tmpref.size = vlen;
	op.params[2].value.a = id;

	res = TEEC_InvokeCommand( sess, CAPSULE_SET_STATE, &op, &ret_orig );
	return check_result( res, "TEEC_InvokeCommand->CAPSULE_SET_STATE", 
					     ret_orig );
}

/* Test command to replace the policy of a trusted capsule. 
 * The command supplies the filename containing the new policy.
 */
TEEC_Result capsule_change_policy( TEEC_Session *sess, 
								   TEEC_SharedMemory *in, 
				            	   char* filename, 
								   uint32_t flen ) {
	uint32_t 	   ret_orig;
	TEEC_Operation op;
	TEEC_Result    res;
	
	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( in->buffer, 0, in->size );

	memcpy( in->buffer, filename, flen );

	op.paramTypes = TEEC_PARAM_TYPES( TEEC_MEMREF_PARTIAL_INPUT,
									  TEEC_NONE,
									  TEEC_NONE,
									  TEEC_NONE );
	
	op.params[0].memref.parent = in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = flen;
	
	res = TEEC_InvokeCommand( sess, CAPSULE_CHANGE_POLICY, 
					          &op, &ret_orig );
	return check_result( res, "TEEC_InvokeCommand->CAPSULE_CREATE", 
					     ret_orig );
}

/* Test command to encrypt a plaintext into trusted capsule
 * form. The command supplies the filename to encapsule.
 */
TEEC_Result capsule_create( TEEC_Session *sess, TEEC_SharedMemory *in, 
				            char* filename, uint32_t flen ) {
	uint32_t 	   ret_orig;
	TEEC_Operation op;
	TEEC_Result    res;
	
	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( in->buffer, 0, in->size );

	memcpy( in->buffer, filename, flen );

	op.paramTypes = TEEC_PARAM_TYPES( TEEC_MEMREF_PARTIAL_INPUT,
									  TEEC_NONE,
									  TEEC_NONE,
									  TEEC_NONE );
	
	op.params[0].memref.parent = in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = flen;
	
	res = TEEC_InvokeCommand( sess, CAPSULE_CREATE, 
					          &op, &ret_orig );
	return check_result( res, "TEEC_InvokeCommand->CAPSULE_CREATE", 
					     ret_orig );
}

/* Test command to decrypt a capsule into plain text. Given a filename,
 * it reads the file and outputs the data. 
 */
TEEC_Result capsule_open( TEEC_Session *sess, TEEC_SharedMemory *in,
				          char* filename, uint32_t flen, int pid, int fd ) {
	uint32_t       ret_orig;
	TEEC_Operation op;
	TEEC_Result    res = TEEC_SUCCESS;

	
	memset( &op, 0, sizeof( TEEC_Operation ) );

	memset( in->buffer, 0, in->size );
	memcpy( in->buffer, filename, flen );

	op.paramTypes = TEEC_PARAM_TYPES( TEEC_MEMREF_PARTIAL_INPUT,
									  TEEC_VALUE_INPUT,
									  TEEC_NONE,
									  TEEC_NONE );
	
	op.params[0].memref.parent = in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = flen;
	op.params[1].value.a = pid;
	op.params[1].value.b = fd;

	res = TEEC_InvokeCommand( sess, CAPSULE_OPEN, &op, 
							  &ret_orig );
	
	return check_result( res,"TEEC_InvokeCommand->CAPSULE_OPEN", 
					     ret_orig );
}

TEEC_Result capsule_read( TEEC_Session *sess, TEEC_SharedMemory *out,
						  char* buf, uint32_t len, uint32_t *nr, int pid,
			   			  int fd ) {
	uint32_t		ret_orig;
	TEEC_Operation  op;
	TEEC_Result     res = TEEC_SUCCESS;

	if( len > out->size ) {
		PRINT_INFO( "Maximum read buffer size is %d B\n", (int) out->size );
		return TEE_ERROR_SHORT_BUFFER;
	}

	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( out->buffer, 0, out->size );

	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,
									  TEEC_MEMREF_PARTIAL_OUTPUT,
									  TEEC_NONE, TEEC_NONE );

	op.params[0].value.a = pid;
	op.params[0].value.b = fd;
	op.params[1].memref.parent = out;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = len;

	res = TEEC_InvokeCommand( sess, CAPSULE_READ, &op, &ret_orig );

	if( res == TEEC_SUCCESS ) {
		memcpy( buf, out->buffer, op.params[1].memref.size );
		*nr = op.params[1].memref.size;
	} else {
		*nr = 0;
	}

	return check_result( res, "TEEC_InvokeCommand->CAPSULE_READ",
						 ret_orig );
}

TEEC_Result capsule_write( TEEC_Session *sess, TEEC_SharedMemory *in,
						   char* buf, uint32_t len, uint32_t *nw, int pid,
			   			   int fd ) {
	uint32_t 		ret_orig;
	TEEC_Operation 	op;
	TEEC_Result 	res = TEEC_SUCCESS;

	if( len > in->size ) {
		PRINT_INFO( "Maximum write buffer size is %d B\n", (int) in->size );
		return TEE_ERROR_SHORT_BUFFER;
	}

	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( in->buffer, 0, in->size );

	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,
									  TEEC_MEMREF_PARTIAL_INPUT,
									  TEEC_NONE, TEEC_NONE );

	op.params[0].value.a = pid;
	op.params[0].value.b = fd;
	op.params[1].memref.parent = in;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = len;

	memcpy( in->buffer, buf, len );

	res = TEEC_InvokeCommand( sess, CAPSULE_WRITE, &op, &ret_orig );
	if( res == TEEC_SUCCESS ) *nw = op.params[1].memref.size;
	else *nw = 0;

	return check_result( res, "TEEC_InvokeCommand->CAPSULE_WRITE",
						 ret_orig );
}


//TODO: not sure if these are necessary, might want to try removing them and see what happens
TEEC_Result capsule_clear_benchmark( TEEC_Session *sess ) {
	
	uint32_t 		ret_orig;
	TEEC_Operation  op;
	TEEC_Result     res = TEEC_SUCCESS;

	memset( &op, 0, sizeof( TEEC_Operation ) );
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_NONE, TEEC_NONE,	
									  TEEC_NONE, TEEC_NONE );

	res = TEEC_InvokeCommand( sess, CAPSULE_CLEAR_BENCHMARK, &op, &ret_orig );
	
	return check_result( res, "TEEC_InvokeCommand->CAPSULE_CLEAR_BENCHMARK", ret_orig );
}

TEEC_Result capsule_collect_benchmark( TEEC_Session *sess ) {
	
	uint32_t 		ret_orig;
	TEEC_Operation  op;
	TEEC_Result     res = TEEC_SUCCESS;

	memset( &op, 0, sizeof( TEEC_Operation ) );
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_NONE, TEEC_NONE,	
									  TEEC_NONE, TEEC_NONE );

	res = TEEC_InvokeCommand( sess, CAPSULE_COLLECT_BENCHMARK, &op, &ret_orig );
	
	return check_result( res, "TEEC_InvokeCommand->CAPSULE_COLLECT_BENCHMARK",
		ret_orig );
}

TEEC_Result capsule_ftruncate( TEEC_Session *sess, uint32_t size ) {
	
	uint32_t 		ret_orig;
	TEEC_Operation  op;
	TEEC_Result     res = TEEC_SUCCESS;

	memset( &op, 0, sizeof( TEEC_Operation ) );
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,
									  TEEC_NONE, TEEC_NONE,
									  TEEC_NONE );

	op.params[0].value.a = size;

	res = TEEC_InvokeCommand(sess, CAPSULE_FTRUNCATE, &op, &ret_orig);
	return check_result( res, "TEEC_InvokeCommand->CAPSULE_FSTAT",
						 ret_orig );
}

TEEC_Result capsule_fstat( TEEC_Session *sess, int pid, 
						   int fd, uint32_t* data_size ) {
	
	uint32_t 		ret_orig;
	TEEC_Operation  op;
	TEEC_Result     res = TEEC_SUCCESS;

	memset( &op, 0, sizeof( TEEC_Operation ) );
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,
				   					  TEEC_VALUE_OUTPUT,	
									  TEEC_NONE,
									  TEEC_NONE );

	op.params[0].value.a = pid;
	op.params[0].value.b = fd;

	res = TEEC_InvokeCommand( sess, CAPSULE_FSTAT, &op, &ret_orig );
	
	*data_size = op.params[1].value.a;
	return check_result( res, "TEEC_InvokeCommand->CAPSULE_FSTAT",
						 ret_orig );
}

TEEC_Result capsule_lseek( TEEC_Session *sess, uint32_t offset, 
				           FILE_POS flag, uint32_t* pos, 
						   int pid, int fd ) {
	
	uint32_t 		ret_orig;
	TEEC_Operation  op;
	TEEC_Result     res = TEEC_SUCCESS;

	memset( &op, 0, sizeof( TEEC_Operation ) );
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,
				   					  TEEC_VALUE_INPUT,	
									  TEEC_VALUE_OUTPUT,
									  TEEC_NONE );

	op.params[0].value.a = pid;
	op.params[0].value.b = fd;
	op.params[1].value.a = offset;
	op.params[1].value.b = flag;

	res = TEEC_InvokeCommand( sess, CAPSULE_LSEEK, &op, &ret_orig );
	
	*pos = op.params[2].value.a;

	return check_result( res, "TEEC_InvokeCommand->CAPSULE_LSEEK",
						 ret_orig );
}

/* Remove the session from handling a particular capsule */
TEEC_Result capsule_close( TEEC_Session *sess, int pid, int fd ) {

	uint32_t 	 	ret_orig;
	TEEC_Operation  op;
	TEEC_Result     res = TEEC_SUCCESS;

	memset( &op, 0, sizeof( TEEC_Operation ) );
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, TEEC_NONE,
									  TEEC_NONE, TEEC_NONE );

	op.params[0].value.a = pid;
	op.params[0].value.b = fd;

	res = TEEC_InvokeCommand( sess, CAPSULE_CLOSE, &op, &ret_orig );
	
	return check_result( res, "TEEC_InvokeCommand->CAPSULE_CLOSE", 
						 ret_orig );
}

/* Open a network connection for the TEE */
TEEC_Result capsule_open_connection( TEEC_Session *sess, TEEC_SharedMemory *in, 
									 char* ip_addr, uint32_t ip_addr_len, 
									 int port, int* fd ) {
	uint32_t       ret_orig;
	TEEC_Operation op;
	TEEC_Result    res = TEEC_SUCCESS;
	
	memset( &op, 0, sizeof( TEEC_Operation ) );

	memset( in->buffer, 0, in->size );
	memcpy( in->buffer, ip_addr, ip_addr_len );
	
	
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_MEMREF_PARTIAL_INPUT,
									  TEEC_VALUE_INPUT,
									  TEEC_VALUE_OUTPUT,
									  TEEC_NONE );
	
	op.params[0].memref.parent = in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = ip_addr_len;
	op.params[1].value.a = port;
	
	res = TEEC_InvokeCommand( sess, CAPSULE_OPEN_CONNECTION, &op, 
							  &ret_orig );
	
	*fd = op.params[2].value.a;
	
	return check_result( res,"TEEC_InvokeCommand->CAPSULE_OPEN_CONNECTION", 
					     ret_orig );
}

/* Write a chunk of data to the network through the TEE */
TEEC_Result capsule_write_connection( TEEC_Session *sess, TEEC_SharedMemory *in, 
									  char* buf, uint32_t blen, int fd, int *nw ) {
	TEEC_Result    res = TEEC_SUCCESS;
	TEEC_Operation op;
	uint32_t       ret_orig;
	
	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( in->buffer, 0, in->size );
	memcpy( in->buffer, buf, blen );
	
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,
									  TEEC_MEMREF_PARTIAL_INPUT,
									  TEEC_NONE,
									  TEEC_NONE );
	
	op.params[0].value.a = fd;
	op.params[1].memref.parent = in;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = blen;
	
	res = TEEC_InvokeCommand( sess, CAPSULE_SEND_CONNECTION, &op, 
							 &ret_orig );
	*nw = op.params[1].memref.size;

	return check_result( res,"TEEC_InvokeCommand->CAPSULE_WRITE_CONNECTION", 
					     ret_orig );
}

/* Read a chunk of data from the network through the TEE */
TEEC_Result capsule_read_connection( TEEC_Session *sess, TEEC_SharedMemory *out,
									 char* buf, uint32_t blen, int fd, int *nr ) {
	uint32_t       ret_orig;
	TEEC_Operation op;
	TEEC_Result    res = TEEC_SUCCESS;
	
	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( out->buffer, 0, out->size );
	memcpy( out->buffer, buf, blen );	

	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,
									  TEEC_MEMREF_PARTIAL_OUTPUT,
									  TEEC_NONE, TEEC_NONE );
	
	op.params[0].value.a = fd;
	op.params[1].memref.parent = out;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = blen;

	res = TEEC_InvokeCommand( sess, CAPSULE_RECV_CONNECTION, &op, 
							  &ret_orig );
	memcpy( buf, out->buffer, op.params[1].memref.size );
	*nr = op.params[1].memref.size;
	return check_result( res,"TEEC_InvokeCommand->CAPSULE_READ_CONNECTION", 
					     ret_orig );
}

/* Close an outstanding network connection */
TEEC_Result capsule_close_connection( TEEC_Session *sess, int fd ) {
	TEEC_Result    res = TEEC_SUCCESS;
	TEEC_Operation op;
	uint32_t       ret_orig;
	
	memset( &op, 0, sizeof( TEEC_Operation ) );
	
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, TEEC_NONE, 
									  TEEC_NONE, TEEC_NONE );
	
	op.params[0].value.a = fd;
	
	res = TEEC_InvokeCommand( sess, CAPSULE_CLOSE_CONNECTION, &op, 
							  &ret_orig );
	
	return check_result( res,"TEEC_InvokeCommand->CAPSULE_CLOSE_CONNECTION",
					     ret_orig );
}

TEEC_Result capsule_send( TEEC_Session *sess, TEEC_SharedMemory *in, 
				          char* buf, uint32_t blen, SERVER_OP s_op, 
						  int rv, int fd, int *nw ) {
	
	TEEC_Result    res = TEEC_SUCCESS;
	TEEC_Operation op;
	uint32_t       ret_orig;
	
	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( in->buffer, 0, in->size );
	memcpy( in->buffer, buf, blen );	
	
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, 
									  TEEC_MEMREF_PARTIAL_INPUT, 
									  TEEC_VALUE_INPUT, 
									  TEEC_NONE );
	
	op.params[0].value.a = fd;
	op.params[1].memref.parent = in;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = blen;
	op.params[2].value.a = s_op;
	op.params[2].value.b = rv;

	res = TEEC_InvokeCommand( sess, CAPSULE_SEND, &op, 
							  &ret_orig );	
	*nw = op.params[1].memref.size;
	return check_result( res, "TEEC_InvokeCommand->CAPSULE_SEND",
					     ret_orig );	
}

TEEC_Result capsule_recv_header( TEEC_Session *sess, TEEC_SharedMemory *out,
			                 	 char* hash, uint32_t hlen, int* recv_plen,
							     int* recv_id, int* recv_op, int* recv_rv,
								 int fd ){
	TEEC_Result    res = TEEC_SUCCESS;
	TEEC_Operation op;
	uint32_t       ret_orig;
	
	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( out->buffer, 0, out->size );
	
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, 
									  TEEC_MEMREF_PARTIAL_OUTPUT, 
									  TEEC_VALUE_OUTPUT,
									  TEEC_VALUE_OUTPUT );
	
	op.params[0].value.a = fd;
	op.params[1].memref.parent = out;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = hlen;	

	res = TEEC_InvokeCommand( sess, CAPSULE_RECV_HEADER, &op, 
							  &ret_orig );
	*recv_id = op.params[2].value.a;
	*recv_op = op.params[2].value.b;
	*recv_plen = op.params[3].value.a;
	*recv_rv = op.params[3].value.b;
	memcpy( hash, out->buffer, op.params[1].memref.size );
	
	return check_result( res,"TEEC_InvokeCommand->CAPSULE_RECV_HEADER",
					     ret_orig );	
}


TEEC_Result capsule_recv_payload( TEEC_Session *sess, 
				                  TEEC_SharedMemory *in, 
								  TEEC_SharedMemory *out, 
								  char* buf, uint32_t blen, 
								  char* hash, uint32_t hlen, 
								  int fd, int *nr ) {
	
	TEEC_Result    res = TEEC_SUCCESS;
	TEEC_Operation op;
	uint32_t       ret_orig;
	
	memset( &op, 0, sizeof( TEEC_Operation ) );
	memset( in->buffer, 0, in->size );
	memcpy( in->buffer, hash, hlen );	
	
	op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, 
									 TEEC_MEMREF_PARTIAL_INPUT, 
									 TEEC_MEMREF_PARTIAL_OUTPUT, 
									 TEEC_NONE );
	
	op.params[0].value.a = fd;
	op.params[1].memref.parent = in;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = hlen;
	op.params[2].memref.parent = out;
	op.params[2].memref.offset = 0;
	op.params[2].memref.size = *nr;
	
	res = TEEC_InvokeCommand( sess, CAPSULE_RECV_PAYLOAD, &op, 
							  &ret_orig );
	if( res == TEEC_SUCCESS ) 
		memcpy( buf, out->buffer, op.params[2].memref.size );
	return check_result( res,"TEEC_InvokeCommand->CAPSULE_RECV_PAYLOAD",
					     ret_orig );	
}

/* Establishes a context with OP-TEE TrustZone as my TEE. */
TEEC_Result initializeContext( TEEC_Context *ctx ) {
	TEEC_Result res;
	res = TEEC_InitializeContext( NULL, ctx );
	return check_result( res, "TEEC_InitializeContext", 0 );
}

/* Session can be opened as single-instance TA or multi-instance TA.
 * This is specified in TEE_Internal_API. It is specified by the TA,
 * how this is achieved specifically in OP-TEE is a mystery
 */
TEEC_Result openSession( TEEC_Context *ctx, TEEC_Session *sess, 
				         TEEC_UUID *uuid ) {
	
	TEEC_Result    res;
	uint32_t       err_origin;
	res = TEEC_OpenSession( ctx, sess, uuid, TEEC_LOGIN_PUBLIC, 
		                    NULL, NULL, &err_origin );
	return check_result( res, "TEEC_OpenSession", err_origin );
}

/* Close session on the TEE side
 */
TEEC_Result closeSession( TEEC_Session *sess ) {
	TEEC_CloseSession( sess );
	return TEEC_SUCCESS;
}

/* Dereference attachment to OP-TEE TrustZone as TEE
 */
TEEC_Result finalizeContext( TEEC_Context *ctx ) {
	TEEC_FinalizeContext( ctx );
	return TEEC_SUCCESS;
}

