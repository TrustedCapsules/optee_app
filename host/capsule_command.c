#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <capsuleCommon.h>
#include <syslog.h>
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

/* Registers an (AES-key pair, keyword) with the Trusted World
 * for encrypt and decrypt operation.
 */

TEEC_Result register_aes_key( TEEC_Session *sess, unsigned char *id,
                              unsigned char *key, size_t keylen, 
                              unsigned char *iv, size_t ivlen, 
                              TEEC_SharedMemory *in ) {
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
                    in ); 
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
    uint32_t       ret_orig;
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
    uint32_t       ret_orig;
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

/*
 * Test command to get internal TA buffer. Should not be used outside of testing
 * buf must be void* because we can get either char* (policy, log, data, 
 * shadow_data) or struct kv_pair*. 
 */
TEEC_Result capsule_get_buffer( TEEC_Session *sess, TEEC_SharedMemory *out, 
                                uint32_t *out_size, char* buf, BUF_TYPE t) {
    uint32_t ret_orig;
    TEEC_Operation op;
    TEEC_Result res;

    memset( &op, 0, sizeof( TEEC_Operation ));
    memset( out->buffer, 0, out->size );

    op.paramTypes = TEEC_PARAM_TYPES ( TEEC_VALUE_INPUT,            // Buf type
                                       TEEC_MEMREF_PARTIAL_OUTPUT,  // Return buf
                                       TEEC_NONE,
                                       TEEC_NONE );

    op.params[0].value.a = t;
    op.params[1].memref.parent = out;
    op.params[1].memref.offset = 0;
    op.params[1].memref.size = *out_size;

    res = TEEC_InvokeCommand( sess, CAPSULE_GET_BUFFER, &op, &ret_orig );

    if( res == TEEC_SUCCESS ) {
        *out_size = op.params[1].memref.size;
        buf = realloc(buf, *out_size);
        if (buf != NULL) {
            memset(buf, 0, *out_size);
            memcpy(buf, out->buffer, *out_size);
            buf[*out_size] = '\0';
            *out_size = *out_size - 1;
        } else {
            *out_size = 0;
            res = TEEC_ERROR_OUT_OF_MEMORY;
            ret_orig = TEEC_ORIGIN_API;
        }
    }

    return check_result( res,"TEEC_InvokeCommand->CAPSULE_GET_BUFFER", 
                         ret_orig );
}


/* Test command to decrypt a capsule into plain text. Given a filename,
 * it reads the file and outputs the data. 
 */
TEEC_Result capsule_open( TEEC_Session *sess, TEEC_SharedMemory *in, 
                          TEEC_SharedMemory *inout, char* filename, 
                          uint32_t name_len, char* contents, 
                          uint32_t file_len, char* decrypted_contents,
                          uint32_t *decrypted_len ) {
    uint32_t       ret_orig;
    TEEC_Operation op;
    TEEC_Result    res = TEEC_SUCCESS;

    // Clear out memory
    memset( &op, 0, sizeof( TEEC_Operation ) );
    memset( in->buffer, 0, in->size );
    memset( inout->buffer, 0, inout->size );

    // Copy data to shared buffers
    memcpy( in->buffer, filename, name_len );
    memcpy( inout->buffer, contents, file_len );

    // Not sure if the partial is necessary or even advantageous considering
    // we are not combining shared memory. 
    op.paramTypes = TEEC_PARAM_TYPES( TEEC_MEMREF_PARTIAL_INPUT, // Filename
                                      TEEC_MEMREF_PARTIAL_INOUT, // File contents
                                      TEEC_NONE,
                                      TEEC_NONE );
    
    // Set input (filename) parameter
    op.params[0].memref.parent = in;
    op.params[0].memref.offset = 0;
    op.params[0].memref.size = name_len;

    // Set inout (file contents) parameter    
    op.params[1].memref.parent = inout;
    op.params[1].memref.offset = 0;
    op.params[1].memref.size = file_len;

    // Invoke the command
    res = TEEC_InvokeCommand( sess, CAPSULE_OPEN, &op, 
                              &ret_orig );
    
    if( res == TEEC_SUCCESS ) {
        *decrypted_len = op.params[1].memref.size;
        decrypted_contents = realloc(decrypted_contents, *decrypted_len + 1);
        if ( decrypted_contents != NULL ) {
            memset(decrypted_contents, 0, *decrypted_len);
            memcpy( decrypted_contents, inout->buffer, *decrypted_len );
            decrypted_contents[*decrypted_len] = '\0';
        } else {
            *decrypted_len = 0;
            res = TEEC_ERROR_OUT_OF_MEMORY;
            ret_orig = TEEC_ORIGIN_API;
        }
    }

    return check_result( res,"TEEC_InvokeCommand->CAPSULE_OPEN", 
                         ret_orig );
}

/* Remove the session from handling a particular capsule */
TEEC_Result capsule_close( TEEC_Session *sess, bool flush, char* contents,
                           uint32_t file_len, TEEC_SharedMemory *in, 
                           TEEC_SharedMemory *out, uint32_t *out_size,
                           char* new_contents ) {

    uint32_t        ret_orig;
    TEEC_Operation  op;
    TEEC_Result     res = TEEC_SUCCESS;

    // Clear memory
    memset( &op, 0, sizeof( TEEC_Operation ) );
    memset( in->buffer, 0, in->size );
    memset( out->buffer, 0, out->size );

    // Initialize input buffer
    memcpy( in->buffer, contents, file_len );

    op.paramTypes = TEEC_PARAM_TYPES( TEEC_VALUE_INPUT,             // fsync/fflush flag
                                      TEEC_MEMREF_PARTIAL_INPUT,    // new file contents
                                      TEEC_MEMREF_PARTIAL_OUTPUT,   // contents to write
                                      TEEC_NONE );

    op.params[0].value.a = (uint32_t) flush;
    op.params[1].memref.parent = in;
    op.params[1].memref.offset = 0;
    op.params[1].memref.size = file_len;
    op.params[2].memref.parent = out;
    op.params[2].memref.offset = 0;
    op.params[2].memref.size = *out_size;

    res = TEEC_InvokeCommand( sess, CAPSULE_CLOSE, &op, &ret_orig );

    if( res == TEEC_SUCCESS ) {
        *out_size = op.params[2].memref.size;
        new_contents = realloc(new_contents, *out_size);
        if ( new_contents != NULL ) {
            memset(new_contents, 0, *out_size);
            memcpy( new_contents, out->buffer, *out_size );
            new_contents[*out_size] = '\0';
        } else {
            *out_size = 0;
            res = TEEC_ERROR_OUT_OF_MEMORY;
            ret_orig = TEEC_ORIGIN_API;
        }
    }
    
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

