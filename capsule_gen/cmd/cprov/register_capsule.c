#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <capsuleCommon.h>
#include <capsuleKeys.h>

TEEC_Result register_keys(char *name , char *path) {
    TEEC_Result     res = TEEC_SUCCESS;
    TEEC_Context    ctx;
    TEEC_Session    sess;
    TEEC_UUID       uuid = CAPSULE_UUID;
    int             i;
    int             found = -1;

    //check if the capsule name exists in pwd. 

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    
    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "register_keys: initializeContext() failed");

    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "register_keys: allocateSharedMem() failed");

    res = openSession( &ctx, &sess, &uuid );
    CHECK_RESULT( res, "register_keys: openSession() failed");

    /* Test key registration */
    PRINT_INFO("register_keys: registering...\n");
    for( i = 0; i < sizeof( capsule_data_array ) /
                    sizeof( struct capsule_data ); i++ ) {
        if( strcmp( capsule_data_array[i].name,name) == 0 ) {
            found = i;
            break;
        }
    }
    
    if( found < 0 ){
        res = TEEC_ERROR_ITEM_NOT_FOUND;
        return res;
    }

    res = register_aes_key( &sess, capsule_data_array[found].id,
                            key_std, sizeof(key_std),
                            iv_std, sizeof(iv_std), 
                            &in_mem );
    CHECK_RESULT( res, "register_keys: register_aes_key() %s failed",
                        capsule_data_array[found].name );
    
    res = closeSession( &sess );
    CHECK_RESULT( res, "register_keys: closeSession()");

    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "register_keys: freeSharedMem()");
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "register_keys: finalizeContext()");

    return res;
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