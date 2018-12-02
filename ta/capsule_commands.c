#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <capsuleCommon.h>
#include <capsuleBenchmark.h>
#include <capsuleServerProtocol.h>
#include <lua.h>
#include <lauxlib.h>
#include "stdlib.h"
#include "capsuleServerProtocol.h"
#include "capsule_structures.h"
#include "capsule_commands.h"
#include "capsule_helper.h"
#include "lua_helpers.h"
#include "capsule_op.h"
#include "capsule_lua_ext.h"
#include "capsule_ta.h"



/* Register an AES key to to Trusted Application. At same time
 * the key is added to persistent storage. 
 */
TEE_Result register_aes_key( uint32_t param_type, 
                             TEE_Param params[4] ) {
    
    ASSERT_PARAM_TYPE( 
        TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
                         TEE_PARAM_TYPE_VALUE_INPUT,
                         TEE_PARAM_TYPE_MEMREF_INPUT,
                         TEE_PARAM_TYPE_MEMREF_INPUT ) 
    );
    
    return do_register_aes( params[0].value.a, 
                            params[1].value.a,
                            params[0].value.b,
                            params[2].memref.buffer, 
                            params[2].memref.size,
                            params[3].memref.buffer, 
                            params[3].memref.size );
}

// /* Sets a local state in the state file */
// TEE_Result set_state( uint32_t param_type,
//                       TEE_Param params[4] ) {

//     TEE_Result res = TEE_SUCCESS;
//     bool       close_after = false;
//     DMSG("in set_State");
//     ASSERT_PARAM_TYPE( 
//         TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,
//                          TEE_PARAM_TYPE_MEMREF_INPUT,
//                          TEE_PARAM_TYPE_VALUE_INPUT,
//                          TEE_PARAM_TYPE_NONE ) );
    
//     /* Open the state file for this trusted capsule */
//     DMSG("in set_State");
//     if( stateFile == TEE_HANDLE_NULL ) {
//         close_after = true;
//         DMSG("in set_State");

//         res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE,
//                                         &params[2].value.a, sizeof( uint32_t ),
//                                         TEE_DATA_FLAG_ACCESS_READ | 
//                                         TEE_DATA_FLAG_ACCESS_WRITE |
//                                         TEE_DATA_FLAG_ACCESS_WRITE_META,    
//                                         &stateFile );
//         id_global_test_02 = params[2].value.a;
//             DMSG("in set_State %d", res);
//         if( res == TEE_ERROR_ITEM_NOT_FOUND ) {
//             DMSG( "First activation...creating state file...0x%08x", params[2].value.a );
//             res = TEE_CreatePersistentObject( TEE_STORAGE_PRIVATE,
//                                               &params[2].value.a, sizeof( uint32_t ),
//                                               TEE_DATA_FLAG_ACCESS_READ | 
//                                               TEE_DATA_FLAG_ACCESS_WRITE |
//                                               TEE_DATA_FLAG_ACCESS_WRITE_META,
//                                               0, NULL, 0, &stateFile );
//             CHECK_GOTO( res, set_state_exit, "TEE_CreatePersistentObject() Error" );
//             DMSG( "State file...0x%08x created", params[2].value.a );
//         } else {
//             CHECK_GOTO( res, set_state_exit, "TEE_OpenPersistentObject() Error" );
//         }
//     }
//     DMSG("in set_State");
//     res = do_set_state( params[0].memref.buffer, params[0].memref.size, 
//                         params[1].memref.buffer, params[1].memref.size );
// set_state_exit:
//     if( close_after ) {
//         TEE_CloseObject( stateFile );
//         stateFile = TEE_HANDLE_NULL;
//     }
//     return res;

// }

// /* Gets a local state in the state file */
// TEE_Result get_state( uint32_t param_type,
//                       TEE_Param params[4] ) {

//     TEE_Result res = TEE_SUCCESS;
//     bool       close_after = false;

//     ASSERT_PARAM_TYPE(
//         TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,
//                          TEE_PARAM_TYPE_MEMREF_OUTPUT,
//                          TEE_PARAM_TYPE_VALUE_INPUT,
//                          TEE_PARAM_TYPE_NONE ) );

//     /* Open the state file for this trusted capsule. Read-Write access */
//     if( stateFile == TEE_HANDLE_NULL ) {
//         close_after = true;
//         res = TEE_OpenPersistentObject( TEE_STORAGE_PRIVATE,
//                                         &params[2].value.a, sizeof( uint32_t ),
//                                         TEE_DATA_FLAG_ACCESS_READ | 
//                                         TEE_DATA_FLAG_ACCESS_WRITE |
//                                         TEE_DATA_FLAG_ACCESS_WRITE_META,
//                                         &stateFile );
//         if( res == TEE_ERROR_ITEM_NOT_FOUND ) {
//             DMSG( "First activation...creating state file...%x", params[2].value.a );
//             res = TEE_CreatePersistentObject( TEE_STORAGE_PRIVATE,
//                                               &params[2].value.a, sizeof( uint32_t ),
//                                               TEE_DATA_FLAG_ACCESS_READ | 
//                                               TEE_DATA_FLAG_ACCESS_WRITE | 
//                                               TEE_DATA_FLAG_ACCESS_WRITE_META,
//                                               0, NULL, 0, &stateFile );
//             CHECK_GOTO( res, get_state_exit, "TEE_CreatePersistentObject() Error" );
//             DMSG( "State file...%x created", params[2].value.a );
//         } else {
//             CHECK_GOTO( res, get_state_exit, "TEE_OpenPersistentObject() Error" );
//         }
//     }
    
//     //Open the device file. Read only 
//    /* if (deviceFile == TEE_HANDLE_NULL)
//     {
        
//         TEE_Result res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
//                                                   &params[2].value.a, sizeof(uint32_t),
//                                                   TEE_DATA_FLAG_ACCESS_READ |
//                                                       TEE_DATA_FLAG_ACCESS_WRITE_META,
//                                                   &deviceFile);
//         if (res == TEE_ERROR_ITEM_NOT_FOUND)
//         {
//             DMSG("First activation...creating device file...%x", params[2].value.a);
//             res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
//                                              &params[2].value.a, sizeof(uint32_t),
//                                              TEE_DATA_FLAG_ACCESS_READ |
//                                                  TEE_DATA_FLAG_ACCESS_WRITE_META,
//                                              0, NULL, 0, &deviceFile);
//             CHECK_GOTO(res, get_state_exit, "TEE_CreatePersistentObject() Error");
//             DMSG("Device file...%x created", params[2].value.a);
//         }
//         else
//         {
//             CHECK_GOTO(res, get_state_exit, "TEE_OpenPersistentObject() Error");
//         }
//     }*/
//     res = do_get_state( params[0].memref.buffer, params[1].memref.buffer,
//                         params[1].memref.size );
//     CHECK_GOTO( res, get_state_exit, "Do_get_state() Error" );

// get_state_exit:
//     if( close_after ) {
//         TEE_CloseObject( stateFile );
//         stateFile = TEE_HANDLE_NULL;
//     }
//     return res;
// }

TEE_Result get_buffer( uint32_t param_type, TEE_Param params[4] ) {
    TEE_Result res = TEE_SUCCESS;
    char *buf;
    size_t len;

    ASSERT_PARAM_TYPE(
            TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,    // Buf type
                             TEE_PARAM_TYPE_MEMREF_OUTPUT,  // Return buf
                             TEE_PARAM_TYPE_NONE,
                             TEE_PARAM_TYPE_NONE
                            ) );

    if( capsule_name == NULL )   {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        CHECK_SUCCESS( res, "No capsule was previously opened" );
    }

    if (cap_head.ref_count == 0) {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        CHECK_SUCCESS( res, "Capsule state already cleared" );
    }

    buf = do_get_buffer( (BUF_TYPE) params[0].value.a, &len, &res );

    switch( (BUF_TYPE) params[0].value.a) {
        case POLICY:
        case KV_STRING:
        case LOG: 
        case DATA:
        case DATA_SHADOW:
            TEE_MemMove(params[1].memref.buffer, buf, len);
            params[1].memref.size = len;
            break;
        default:
            res = TEE_ERROR_NOT_SUPPORTED;
    }

    return res;
}

/* Opens a capsule for this TA session */
TEE_Result capsule_open( uint32_t param_type, 
                         TEE_Param params[4] ) {
    
    TEE_Result      res = TEE_SUCCESS;
    unsigned char   credential[STATE_SIZE];
    unsigned char  *file_contents;
    size_t          file_len;
    unsigned char  *kvs;
    struct kv_pair *temp;
    ASSERT_PARAM_TYPE( 
           TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,    // File name
                            TEE_PARAM_TYPE_MEMREF_INOUT,    // File contents
                            TEE_PARAM_TYPE_NONE,
                            TEE_PARAM_TYPE_NONE
                          ) );

    // Check to see if this is the correct session for this capsule
    DMSG("1");
    if (capsule_name == NULL)
    {
        capsule_name = TEE_Malloc( params[0].memref.size + 1, 0 );
        TEE_MemMove( capsule_name, params[0].memref.buffer, 
                params[0].memref.size );
        capsule_name[ params[0].memref.size ] = '\0';
    
        DMSG( "Created new capsule session %s (%d B)", 
             capsule_name, params[0].memref.size );
    } else {
        DMSG("2\n");
        if( strncmp( capsule_name, 
                     params[0].memref.buffer, 
                     strlen( capsule_name ) ) != 0 ) {
            DMSG( "Input name does not match capsule name %s", capsule_name );
            return TEE_ERROR_NOT_SUPPORTED;
        }
    }
    DMSG( "Opening Trusted Capsule session...%s - curr_ts %d", 
          capsule_name, curr_ts );

    // Create the file contents buffer
    DMSG("here");
    file_len = params[1].memref.size + 1;
    DMSG("here");
    file_contents = TEE_Malloc( file_len, 0);
    DMSG("here");
    TEE_MemMove( file_contents, params[1].memref.buffer, params[1].memref.size );
    DMSG("here");
    file_contents[params[1].memref.size] = '\0';
    DMSG("here");
    // Open the file (initializes the capsule structure)
    res = do_open( file_contents, params[1].memref.size );
    DMSG("here");
    CHECK_GOTO( res, capsule_open_exit, "Do_open() Error" );

    // Setup Lua (if this is the first time using it)
    if( Lstate == NULL ) {
        MSG( "Initializing Interpreter..." );
        lua_start_context( &Lstate );
        DMSG("here");
        res = do_load_policy();
        CHECK_GOTO( res, capsule_open_exit, "Do_load_policy() Error" );
        res = lua_add_ext( Lstate );
        CHECK_GOTO( res, capsule_open_exit, "Add_lua_ext() Error" );
    }

    //TODO: Commenting out the statefile stuff till I figure out what it does. 
    ///* Open the state file for this trusted capsule */
    // if( stateFile == TEE_HANDLE_NULL ) {
    //     res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
    //                                    &symm_id, sizeof(uint32_t),
    //                                    TEE_DATA_FLAG_ACCESS_READ |
    //                                    TEE_DATA_FLAG_ACCESS_WRITE |
    //                                    TEE_DATA_FLAG_ACCESS_WRITE_META,
    //                                    &stateFile);
    //     if (res == TEE_ERROR_ITEM_NOT_FOUND)
    //     {
    //         DMSG("First activation...creating state file...%d", symm_id);
    //         res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
    //                                          &symm_id, sizeof(uint32_t),
    //                                          TEE_DATA_FLAG_ACCESS_READ |
    //                                          TEE_DATA_FLAG_ACCESS_WRITE |
    //                                          TEE_DATA_FLAG_ACCESS_WRITE_META,
    //                                          0, NULL, 0, &stateFile);
    //         CHECK_GOTO(res, capsule_open_exit, "TEE_CreatePersistentObject() Error");
    //         DMSG("State file...%x created", params[2].value.a);
    //     }
    //     else
    //     {
    //         CHECK_GOTO(res, capsule_open_exit, "TEE_OpenPersistentObject() Error");
    //     }
        
    // }

    // res = do_get_state( (unsigned char*) TZ_CRED, credential, STATE_SIZE );
    // CHECK_GOTO( res, capsule_open_exit, "Do_get_state() Error" );

    // this line throws a warning because converting an unsigned char* to a
    // void* to an int*. Then it is dereferenced into an int. We should figure
    // out a cleaner way to doing this. The values are stored as strings.
    //curr_cred = *(int*)(void*)(credential); TODO: removing this for now.

    curr_len = 0;

    
    for(temp = (&cap_head)->kv_store; temp!=NULL; temp = temp->hh.next){
        DMSG("\nkey is %s, value is %s\n", temp->key, temp->value);
    }
    
    // Run the policy
    DMSG("policy func string %s", POLICY_FUNC);
    DMSG("policy op %d", OPEN_OP); 
    res = do_run_policy( Lstate, POLICY_FUNC, OPEN_OP );
    // Clear the return buffer
    TEE_MemFill(params[1].memref.buffer, 0, params[1].memref.size);

    if( res != TEE_SUCCESS ) {
        // If nothing else is pointing to this capsule, clear the context
        // and return an empty buffer to FUSE
        if (cap_head.ref_count == 0) {
            finalize_capsule_text(&cap_head);
        }
        goto capsule_open_exit;
    }
    //TODO: set a read_only flag in the return params. 

    // Copy over shadow copy (policy can modify this buffer)
    // QUESTION: what happens if the buffer is bigger? Do we allow the policy to 
    //           add more data?
    // If so, we should have a relloc on the buffer, not sure if that's possible?
    TEE_MemMove(params[1].memref.buffer, cap_head.data_shadow_buf, 
                cap_head.data_shadow_len + 1); 
    params[1].memref.size = cap_head.data_shadow_len;

    // Increment reference counter for debugging
    cap_head.ref_count++;
    int len_kvs = get_kv_string_len();
    kvs = TEE_Malloc(len_kvs, 0);
    serialize_kv_store(kvs, len_kvs);
    int i = 0;
    while (i < len_kvs)
    {
        if (kvs[i] == '\0')
        {
            DMSG("\nfound \\0 at i = %d\n", i);
        }
        i++;
    }
    DMSG("\n the kv store is : %s \n", kvs);

capsule_open_exit:
    // Clean up malloc'd memory. File contents should have been copied
    // into the capsule buffers. 
    // NOTE: This throws a weird memory corruption error
    // TEE_Free(file_contents);

    return res;
}

/* Reset all global variables that manage capsule state */
TEE_Result capsule_close(uint32_t param_type, TEE_Param params[4]) {

    TEE_Result      res = TEE_SUCCESS;
    unsigned char  *new_contents;
    size_t          new_len = 0;

    // MSG("Capsule ref_count = %d", cap_head.ref_count);
    if( capsule_name == NULL ) {
        res = TEE_ERROR_ITEM_NOT_FOUND;             
        CHECK_SUCCESS( res, "No capsule was previously opened" );
    } 

    if (cap_head.ref_count == 0) {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        CHECK_SUCCESS( res, "Capsule state already cleared" );
    }
    
    ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,     // fsync/fflush flag
                                        TEE_PARAM_TYPE_MEMREF_INPUT,    // New file contents
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,   // Contents to write
                                        TEE_PARAM_TYPE_NONE ) );

    // Free the shadow buffer if it is allocated
    if (cap_head.data_shadow_buf != NULL) {
        TEE_Free(cap_head.data_shadow_buf);
        cap_head.data_shadow_len = 0;
    }
    //TODO: this ^ might change for read-only access. put an if condition here.
    // Setup the shadow buffer
    cap_head.data_shadow_buf = TEE_Malloc(params[1].memref.size, 0);
    TEE_MemMove(cap_head.data_shadow_buf, 
                params[1].memref.buffer, 
                params[1].memref.size);
    cap_head.data_shadow_len = params[1].memref.size;
    DMSG("\ncapsule data buffer is:\n%s\n", cap_head.data_buf);
    DMSG("\ncapsule shadow buffer is:\n%s\n",cap_head.data_shadow_buf);
    DMSG("\ncapsule policy buffer is:\n%s\n", cap_head.policy_buf);
    DMSG("\ncapsule log buffer is:\n%s\n", cap_head.log_buf);

    // Run the policy
    DMSG("\n\n\nHERE IN CLOSE\n\n\n");
    res = do_run_policy( Lstate, POLICY_FUNC, CLOSE_OP );

    // Construct the encrypted file and clear all buffers
    new_contents = do_close( res, &new_len, params[0].value.a );

    // Setup return parameter with encrypted file
    TEE_MemMove(params[2].memref.buffer, new_contents, new_len);
    params[2].memref.size = new_len;

    // Free allocated memory
    // NOTE: this causes a memory corruption error when uncommented
    // TEE_Free(new_contents);

    return res;
}

/**
 * Necessary for networking tests
 */
TEE_Result capsule_open_connection( uint32_t param_type, TEE_Param params[4] ) {
    TEE_Result res = TEE_SUCCESS;
    int        fd = -1;
    char       ip_addr[16];

    ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_VALUE_INPUT,
                                        TEE_PARAM_TYPE_VALUE_OUTPUT,
                                        TEE_PARAM_TYPE_NONE ) );

    memcpy( ip_addr, params[0].memref.buffer, params[0].memref.size );

    res = do_open_connection( ip_addr, params[1].value.a, &fd );
    CHECK_SUCCESS( res, "Do_open_connection() Error" );
    
    params[2].value.a = fd;
    return res;
}

TEE_Result capsule_close_connection( uint32_t param_type, TEE_Param params[4] ) {
    TEE_Result res = TEE_SUCCESS;

    ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE ) );

    res = do_close_connection( params[0].value.a );
    CHECK_SUCCESS( res, "Do_close_connection() Error" );    
    
    return res;
}

TEE_Result capsule_recv_connection( uint32_t param_type, TEE_Param params[4] ) {
    TEE_Result res = TEE_SUCCESS;

    ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_NONE, 
                                        TEE_PARAM_TYPE_NONE ) );
    
    res = do_recv_connection( params[0].value.a, params[1].memref.buffer, 
                              (int*) &params[1].memref.size );
    
    CHECK_SUCCESS( res, "Do_recv_connection() Error" );
    return res;
}

TEE_Result capsule_send_connection( uint32_t param_type, TEE_Param params[4] ) {
    TEE_Result res = TEE_SUCCESS;

    ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE ) );

    res = do_send_connection( params[0].value.a, params[1].memref.buffer,
                              (int*) &params[1].memref.size );

    CHECK_SUCCESS( res, "Do_send_connection() Error" );

    return res;
}

TEE_Result capsule_send( uint32_t param_type, TEE_Param params[4] ) {   
    
    TEE_Result res = TEE_SUCCESS;

    ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_INPUT, 
                                        TEE_PARAM_TYPE_VALUE_INPUT,
                                        TEE_PARAM_TYPE_NONE ) );    
        
    res = do_send( params[0].value.a, params[1].memref.buffer, 
                   (size_t) params[1].memref.size, params[2].value.a,
                   params[2].value.b );
    CHECK_SUCCESS( res, "Do_send() Error" );
    
    return res;     
}   

TEE_Result capsule_recv_payload( uint32_t param_type, TEE_Param params[4] ) {   
    
    TEE_Result res = TEE_SUCCESS;

    ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_NONE ) );    
        
    res = do_recv_payload( params[0].value.a, params[1].memref.buffer,
                           params[1].memref.size, params[2].memref.buffer,
                           params[2].memref.size );
    CHECK_SUCCESS( res, "Do_recv_payload() Error" );
    return res;     
}

TEE_Result capsule_recv_header( uint32_t param_type, TEE_Param params[4] ) {    
    
    TEE_Result  res = TEE_SUCCESS;
    msgReplyHeader   msg = {0};

    ASSERT_PARAM_TYPE( TEE_PARAM_TYPES( TEE_PARAM_TYPE_VALUE_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_VALUE_OUTPUT,
                                        TEE_PARAM_TYPE_VALUE_OUTPUT ) );    
        
    res = do_recv_header( params[0].value.a, &msg );
    CHECK_SUCCESS( res, "Do_recv_header() Error" );

    memcpy( params[1].memref.buffer, msg.hash, HASHLEN );
    params[1].memref.size = HASHLEN;
    params[2].value.a = msg.capsuleID;
    params[2].value.b = msg.response;
    params[3].value.a = msg.nonce;
    params[3].value.b = msg.payloadLen;

    return res;     
}   
