#include <stdio.h>
#include <string.h>
#include "err_ta.h"
#include "key_data.h"

void add_attr( size_t attr_count, TEE_Attribute *attrs, 
			   uint32_t attr_id, const void *buf, size_t len ) {
	attrs[attr_count].attributeID = attr_id;
	attrs[attr_count].content.ref.buffer = (void *) buf;
	attrs[attr_count].content.ref.length = len;
}

TEEC_Result pack_attrs( const TEE_Attribute *attrs, 
				        uint32_t attr_count, uint8_t *buf, 
						size_t *blen, size_t max_size ) {
	
	int n;
	struct tee_attr_packed* a;
	uint8_t* p;

	/* First calculate the length required to store all the attrs.
	 * This must be less than the size of the TEEC_SharedMemory
	 */

	if( attr_count == 0 ) 
		return TEE_SUCCESS;

	*blen = sizeof( uint32_t ) + 
			sizeof( struct tee_attr_packed ) * attr_count;
	
	for( n = 0; n < attr_count; n++ ) {
		if( ( attrs[n].attributeID & TEE_ATTR_BIT_VALUE ) != 0 )
			continue;
		if( !attrs[n].content.ref.buffer )
			continue;		
		
		*blen += ROUNDUP( attrs[n].content.ref.length, 4 );
	}

	if( *blen > max_size ) 
		   return TEE_ERROR_OUT_OF_MEMORY; 

	/* Memcpy the content of each TEE_Attribute to the buffer.
	 */
	p = buf;
	*( uint32_t* ) ( void* )p = attr_count;
	p += sizeof( uint32_t );
	a = ( struct tee_attr_packed* ) ( void* )p;
	p += sizeof( struct tee_attr_packed) * attr_count;

	for( n = 0; n < attr_count; n++ ) {
		a[n].attr_id = attrs[n].attributeID;
		if( attrs[n].attributeID & TEE_ATTR_BIT_VALUE ) {
			a[n].a = attrs[n].content.value.a;
			a[n].b = attrs[n].content.value.b;
			continue;
		}

		a[n].b = attrs[n].content.ref.length;

		if( !attrs[n].content.ref.buffer ) {
			a[n].a = 0;
			continue;
		}

		a[n].a = ( uint32_t ) ( uintptr_t ) ( p - buf );
		memcpy( p, attrs[n].content.ref.buffer, 
				attrs[n].content.ref.length );
		
		/* Round up to the next point in the buffer that is aligned */
		p += ROUNDUP( attrs[n].content.ref.length, 4 );
	}

	return TEE_SUCCESS;
}

void create_rsa_key( TEEC_Operation *op, uint32_t max_key_size, 
				     uint32_t key_type, TEE_Attribute *attrs, 
					 size_t num_attrs, TEEC_SharedMemory* in ) {

	uint8_t *buf = ( uint8_t* ) in->buffer;
	size_t blen;

	pack_attrs( attrs, num_attrs, buf, &blen, in->size );

	op->params[0].value.a = key_type;
	op->params[0].value.b = max_key_size;

	op->params[1].memref.parent = in;
	op->params[1].memref.offset = 0;
	op->params[1].memref.size = blen;	
 	
	op->paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, 
		      						   TEEC_MEMREF_PARTIAL_INPUT,
					  				   TEEC_NONE, TEEC_NONE );

}

void create_aes_key( TEEC_Operation *op, uint32_t max_key_size, 
	                 uint32_t key_type, unsigned char* id, 
					 TEE_Attribute *attrs, size_t num_attrs, 
					 uint8_t* iv, size_t iv_len, 
					 TEEC_SharedMemory* in, uint32_t chunk_size ) {
	
	uint8_t *buf = ( uint8_t* ) in->buffer;
	size_t blen;

	pack_attrs( attrs, num_attrs, buf, &blen, in->size );

	op->params[0].value.a = key_type;
	op->params[0].value.b = max_key_size;
	op->params[1].value.a = * (uint32_t*) (void*) (id);
	op->params[1].value.b = chunk_size;	
	op->params[2].memref.parent = in;
	op->params[2].memref.offset = 0;
	op->params[2].memref.size = blen;
	op->params[3].tmpref.buffer = (void *) iv;
	op->params[3].tmpref.size = iv_len;

	op->paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT, 
									   TEEC_VALUE_INPUT,
									   TEEC_MEMREF_PARTIAL_INPUT,
									   TEEC_MEMREF_TEMP_INPUT );

}
