#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include "err_ta.h"
#include "key_data.h"
#include <capsule_command.h>
#include <capsuleKeys.h>
#include <tee_api_types.h>
#include <tee_client_api.h>

TEEC_Result register_aes_key( TEEC_Session *sess, unsigned const char *id,
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

TEEC_Result registerCapsule (char *name , char *path) {
    TEEC_Result     res = TEEC_SUCCESS;
    TEEC_Context    ctx;
    TEEC_Session    sess;
    TEEC_UUID       uuid = CAPSULE_UUID;
    uint32_t        err_origin;
    int             i;
    int             found = -1;

    //check if the capsule name exists at the path
    int combined_len = strlen(name) + strlen(path)+10;
    char *abs_path = (char*)malloc(combined_len);
    abs_path[0]="\0";
    if(path[strlen(path)-1] == '/') //Remove trailing backslash
        path[strlen(path)-1] = '\0';
    sprintf(abs_path, "%s/%s.capsule",path,name);
    if( access( abs_path, F_OK ) == -1 ){
        printf( "The file %s does not exist\n", abs_path );
        res = TEEC_ERROR_ITEM_NOT_FOUND;
        return res;
    }

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    
    res = TEEC_InitializeContext( NULL, &ctx );
    CHECK_RESULT( res, "registerCapsule: TEEC_InitializeContext() failed");

    res = TEEC_AllocateSharedMemory( &ctx, &in_mem );
    CHECK_RESULT ( res, "registerCapsule: TEEC_AllocateSharedMemory() failed" );
    
    
    res = TEEC_OpenSession( &ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, 
                            NULL, NULL, &err_origin );
    CHECK_RESULT( res, "registerCapsule: TEEC_OpenSession() failed");

    /* Test key registration */
    PRINT_INFO("registerCapsule: registering...\n");
    for( i = 0; i < sizeof( capsule_data_array ) /
                    sizeof( struct capsule_data ); i++ ) {
        printf("capsule_data entry %s",capsule_data_array[i].name);
        if( strcmp( capsule_data_array[i].name,name) == 0 ) {
            found = i;
            break;
        }
    }
    
    if( found < 0 ){
        res = TEEC_ERROR_ITEM_NOT_FOUND;
        CHECK_RESULT(res, "The key was not found in capsuleKeys.h" );
    }

    res = register_aes_key( &sess, capsule_data_array[found].id,
                            keyDefault, sizeof(keyDefault),
                            ivDefault, sizeof(ivDefault), 
                            &in_mem );
    CHECK_RESULT( res, "registerCapsule: register_aes_key() %s failed",
                        capsule_data_array[found].name );
    
    TEEC_CloseSession( &sess );
    TEEC_ReleaseSharedMemory( &in_mem );
    TEEC_FinalizeContext( &ctx );
    res = TEEC_SUCCESS;
    PRINT_INFO(" finished the registration ");
    return res;
}