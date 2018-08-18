#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>
#include <stdlib.h>
//#include <string.h>
#include <capsuleCommon.h>
#include <capsulePolicy.h>
#include <capsuleServerProtocol.h>
#include <capsuleKeys.h>
#include <lua.h>
#include "capsule_structures.h"
#include "capsule_helper.h"
#include "network_helper.h"
#include "lua_helpers.h"
#include "capsule_op.h"
#include "capsule_ta.h"

TEE_Result do_register_aes( uint32_t keyType, uint32_t id, uint32_t keyLen, 
                            uint8_t* attr, uint32_t attrlen,
                            uint8_t* iv, uint32_t ivlen ) {

    TEE_Result      res = TEE_SUCCESS;
    uint32_t        total_size;
    uint8_t        *data_buffer;
    uint8_t        *it;

    if( keyType != TEE_TYPE_AES ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "Non-AES keys are not supported" ); 
    }
    
    /* Add the key to persistent storage in a serial manner.
     * => Total size, key size, key id, iv size, iv, attrs 
     */
    if( keyFile != TEE_HANDLE_NULL ) {

        res = TEE_SeekObjectData( keyFile, 0, TEE_DATA_SEEK_END );
        CHECK_SUCCESS( res, "TEE_SeekObjectData() Error" );
        
        // Should be 4 instead of 5. (remove chunk size)
        total_size = attrlen + ivlen + 5*sizeof(uint32_t);
        
        DMSG( "Write %u B of AES key 0x%08x to sec. storage",
             total_size, id );

        data_buffer = TEE_Malloc( total_size, 0 );
        it = data_buffer;

        //total_size less size of total_size 
        *(uint32_t*) (void*) it = total_size - sizeof(uint32_t);
        DMSG( "First 4 bytes: %u", *(uint32_t*)(void*) it );       
        it += sizeof(uint32_t);

        //key_len
        *(uint32_t*) (void*) it = keyLen;                
        DMSG( "Second 4 bytes: %u", *(uint32_t*)(void*) it );       
        it += sizeof(uint32_t);

        //key_id
        *(uint32_t*) (void*) it = id;               
        DMSG( "Third 4 bytes: %08x", *(uint32_t*)(void*) it );    
        it += sizeof(uint32_t);

        //iv_size
        *(uint32_t*) (void*) it = ivlen;            
        DMSG( "Fourth 4 bytes: %u", *(uint32_t*)(void*) it );      
        it += sizeof(uint32_t);

        //iv
        memcpy( it, iv, ivlen );
        it += ivlen;

        //aes key_attr
        memcpy( it, attr, attrlen ); 

        res = TEE_WriteObjectData( keyFile, data_buffer, total_size );
        CHECK_SUCCESS( res, "TEE_WriteObjectData() Error" );
        
        TEE_Free( data_buffer );
    } else {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "No keyfile found!" );
    }

    return res;

}

TEE_Result do_open( unsigned char* file_contents, int file_size ) {

    TEE_Result          res = TEE_SUCCESS;
    struct TrustedCap   header;
    unsigned char       ptx[file_size];     // The plain text can be no bigger 
                                            // than the capsule size
    size_t              ptxlen = file_size;
    int                 init_ctr = 0;

    // Initialize the capsule's text index structure and header if this is the 
    // first open call. Otherwise, everything is already loaded and we 
    // increment the ref_count.
    if( cap_head.ref_count == 0 ) {
        // Initialize our global capsule
        initialize_capsule_text( &cap_head );

        // Read in and initialize the header variable
        read_header(file_contents, &header);

        // If we have not loaded key info (again global), do so.
        if( aes_key_setup == false ) {
            res = find_key( &header, keyFile, &decrypt_op, &encrypt_op,
                            &hash_op, &symm_id, &symm_iv_len, &symm_key_len,
                            &symm_iv );
            CHECK_SUCCESS( res, "Find_key() Error" );   
            aes_key_setup = true;
        }

        // Copy the header variable into our global struct
        TEE_MemMove(&cap_head.header, &header, sizeof(struct TrustedCap));
        
        // Decrypt the entire file (starting after the header)
        res = process_aes_block(file_contents + sizeof(struct TrustedCap), 
                                file_size - sizeof(struct TrustedCap), ptx, 
                                &ptxlen, symm_iv, symm_iv_len, 
                                init_ctr, true, true, decrypt_op);
        // Insert null terminator for string
        ptx[ptxlen] = '\0';

        // Parse out the file into specific buffers. 
        DMSG("\n\nsepparts\n\n");
        sep_parts(ptx, ptxlen, &cap_head);
    }

    // Increase the reference count for this capsule
    // cap_head.ref_count++;

    return res;
}

unsigned char* do_close( TEE_Result policy_res, size_t *cap_to_write_len, 
                         bool flush_flag ) {
    TEE_Result      res = TEE_SUCCESS;

    unsigned char  *concatenated_data,  // Holds the concatenated data (policy, kv, log, data)
                   *encrypted_data,     // encrypted version of concatenated data
                   *cap_to_write,       // header + encrypted contents to write
                   *data,               // capsule data (original data or shadow buf)
                   *kvstore;            // key-value store string

    size_t          datalen,            // length of data buffer
                    encrypt_len,        // length of concatenated and encrypted buffers
                    kv_len = 0,         // length of kv string
                    header_len,         // size of header
                    hlen = HASHLEN;    // length of hash (should be 32)

    int             last = 0,           // current append spot in concat data
                    init_ctr = 0;       // initial counter for hash

    unsigned char   hash[HASHLEN];     // new hash for encrypted data

    if (policy_res != TEE_SUCCESS) {
        // If the policy did not pass, use data buffer
        data = cap_head.data_buf;
        datalen = cap_head.data_len;
    } else {
        // If the policy passed, we need to use the requested write data
        data = cap_head.data_shadow_buf;
        datalen = cap_head.data_shadow_len;
    }

    // Get length of KV string
    kv_len = get_kv_string_len();

    // Allocate space for the kv store string buffer
    kvstore = TEE_Malloc(kv_len, 0);

    // Serialize the kv struct array into a string
    serialize_kv_store(kvstore, kv_len);

    // Calculate lengths
    encrypt_len = cap_head.policy_len + cap_head.log_len + 
                  kv_len + datalen + DELIMITER_SIZE*3 - 3;
    header_len = sizeof(cap_head.header);
    *cap_to_write_len = encrypt_len + header_len;

    // Allocate buffer to fit new capsule
    cap_to_write = TEE_Malloc( *cap_to_write_len, 0 );

    // Allocate buffer to hold concatenated data and encrypted data
    concatenated_data = TEE_Malloc( encrypt_len, 0 );
    encrypted_data = TEE_Malloc(encrypt_len, 0);

    // Concatenate all the buffers for encryption. Subtract 1 from the policy,
    // k-v store, and log length (removes their null terminators).
    TEE_MemMove(concatenated_data, cap_head.policy_buf, cap_head.policy_len - 1);
    last += cap_head.policy_len - 1;
    TEE_MemMove(concatenated_data + last, DELIMITER, DELIMITER_SIZE);
    last += DELIMITER_SIZE;
    TEE_MemMove(concatenated_data + last, kvstore, kv_len - 1);
    last += kv_len - 1;
    TEE_MemMove(concatenated_data + last, DELIMITER, DELIMITER_SIZE);
    last += DELIMITER_SIZE;
    TEE_MemMove(concatenated_data + last, cap_head.log_buf, cap_head.log_len - 1);
    last += cap_head.log_len - 1;
    TEE_MemMove(concatenated_data + last, DELIMITER, DELIMITER_SIZE);
    last += DELIMITER_SIZE;
    TEE_MemMove(concatenated_data + last, data, datalen);
    last += datalen;

    // Make sure the concatenated_data string ends with a null terminator
    concatenated_data[last] = '\0';

    // Encrypt the data into a temp string (encrypted_data)
    res = process_aes_block(concatenated_data, encrypt_len, encrypted_data, 
                            &encrypt_len, symm_iv, symm_iv_len, init_ctr, true,
                            true, encrypt_op);
    if( res != TEE_SUCCESS ) {
        MSG( "process_aes_block() Error" );
        return NULL;
    }

    // TODO: add better error handling
    // Update header hash values and size
    res = hash_block(encrypted_data, encrypt_len, hash, hlen, true, hash_op);
    if( res != TEE_SUCCESS ) {
        DMSG( "hash_block() Error" );
        return NULL;
    }

    // TA side check for no-op capsule (i.e., hash should not change)    
    // for (unsigned int i = 0; i < hlen; i++) {
    //     if (cap_head.header.hash[i] != hash[i]) {
    //         DMSG("%d: %02x != %02x", i, cap_head.header.hash[i], hash[i]);
    //     }
    // }

    TEE_MemMove(&cap_head.header.hash, hash, hlen);


    // Fill in the new header
    res = fill_header(&cap_head.header, encrypt_op, symm_iv, symm_iv_len, 
                      symm_id, hash, hlen, encrypt_len);
    if( res != TEE_SUCCESS ) {
        MSG( "fill_header() Error" );
        return NULL;
    }

    // Copy header to write buffer
    TEE_MemMove(cap_to_write, &cap_head.header, header_len);

    // Append encrypted data to write buffer
    TEE_MemMove(cap_to_write + header_len, encrypted_data, encrypt_len);

    if (!flush_flag) {
        // If we are not just flushing, decrease the reference count
        cap_head.ref_count--;
    }

    if (cap_head.ref_count == 0) {
        // Clear out the buffers if this is the last reference to the capsule
        finalize_capsule_text(&cap_head);
    }

    // Return the capsule to write
    return cap_to_write;
}

/* Run the Lua policy function - if the policy was changed,
 *                               run it again */
TEE_Result do_run_policy( lua_State *L, const char* policy, SYSCALL_OP n ) { 

    int  res = TEE_SUCCESS, ret = LUA_OK;
    int  cur_stack = lua_gettop(L);
    bool eval, pol_changed;
    uint64_t cnt_a, cnt_b;
    DMSG("\npolicy string is %s",policy);

    cnt_a = read_cntpct();
    do {
        /* Call lua policy function */
        DMSG("\n\n");
        lua_getglobal( L, policy );
        DMSG("\n\n");
        lua_pushnumber( L, n ); /* policy takes a number argument */
        DMSG("\n\n");
        ret = lua_pcall( L, 1, 2, 0 );
        if( ret != LUA_OK ) {
            res = TEE_ERROR_NOT_SUPPORTED;
            CHECK_SUCCESS( res, "error running func '%s:%d': %s",
                                policy, n, lua_tostring( L, -1 ) ); 
        }

        if( !lua_isboolean( L, -1 ) ) {
            res = TEE_ERROR_NOT_SUPPORTED;
            CHECK_SUCCESS( res, "Func '%s:%d' must return a boolean",
                                policy, n );
        }

        pol_changed  = lua_toboolean( L, -1 );
        DMSG( "Function '%s:%d' pol_changed is %s", policy, n,
          pol_changed == true ? "true" : "false" );
        
        if( pol_changed ) {
            /* reload the policy since it has changed */
            do_load_policy();
        }
    
    } while( pol_changed == true );

    if( !lua_isboolean( L, -2 ) ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "Func '%s:%d' must return a boolean",
                            policy, n );
    }

    eval = lua_toboolean( L, -2 );
    DMSG( "Function '%s:%d' evaluated to %s", policy, n,
      eval == true ? "true" : "false" );
    if( eval == false ) {
        res = TEE_ERROR_POLICY_FAILED;
    }
    
    /* Clear the effects of this function */
    lua_settop( L, cur_stack );

    cnt_b = read_cntpct(); 
    timestamps[curr_ts].policy_eval += cnt_b - cnt_a;
    return res;
}

TEE_Result do_load_policy(void) {
    
    TEE_Result     res = TEE_SUCCESS;
    uint64_t       cnt_a, cnt_b;

    cnt_a = read_cntpct();

    /* Load the policy into Lua */
    DMSG("\npolicy text is %s\n\n\n",cap_head.policy_buf);
    res = lua_load_policy( Lstate, (const char*) cap_head.policy_buf );
    CHECK_SUCCESS( res, "load_policy() Error" );

    cnt_b = read_cntpct();
    timestamps[curr_ts].policy_eval += cnt_b - cnt_a;
    return res;
}

/**
 * Needed for lua check policy changed
 */
TEE_Result do_write_new_policy_network( unsigned char* policy, 
                                        uint32_t len ) {
    
    TEE_Result res = TEE_SUCCESS;

    // If the new length is not the same as the current len, then resize the 
    // buffer
    if (len != cap_head.policy_len) {
        cap_head.policy_buf = TEE_Realloc(cap_head.policy_buf, len);
    }

    // Copy the new data over to the buffer.
    memcpy(cap_head.policy_buf, (const char *) policy, len);

    return res; 
}

/* We use this to change policy over the network */
TEE_Result do_change_policy_network( unsigned char* policy, 
                                     size_t newlen ) {
    
    TEE_Result res = TEE_SUCCESS;

    /* 
     * 1. Write the new policy to the buffer
     *
     * Hash update and header updates on write (where everything changes.)
     */

    /* Read in and write out the new policy */
    res = do_write_new_policy_network( policy, newlen );
    CHECK_SUCCESS( res, "Write_new_policy() Error" );

    return res;
}

TEE_Result do_open_connection( char* ip_addr, int port, int* fd ) {
    TEE_Result res = TEE_SUCCESS;
    uint64_t   cnt_a, cnt_b;
    /* For now, we crash the program if errors are encountered.
     * This may change as we build out the network protocol
     */ 
    cnt_a = read_cntpct();
    res = TEE_SimpleOpenConnection( ip_addr, port, fd );
    cnt_b = read_cntpct();
    timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
    if( res != TEE_SUCCESS ) {
        MSG( "TEE_SimpleOpenConnection() Error: fd is %d", *fd );
    }

    /* Currently we do not maintain the state (e.g., open fd) in the
     * optee ap or the optee os. This is left for future work.
     */

    //MSG( "IP Addr: %s, Port: %d\n, fd: %d", ip_addr, port, *fd );
    return res;
}

TEE_Result do_close_connection( int fd ) {
    TEE_Result res = TEE_SUCCESS;
    uint64_t   cnt_a, cnt_b;
    /* For now, we crash the program if errors are encountered.
     * This may change as we build out the network protocol
     */ 
    cnt_a = read_cntpct();
    if( TEE_SimpleCloseConnection( fd ) != TEE_SUCCESS ) {
        MSG( "TEE_SimpleCloseConnection() error: fd->%d", fd );
    }
    cnt_b = read_cntpct();
    timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;

    return res;
}

TEE_Result do_recv_connection( int fd, void *buf, int *len ) {
    TEE_Result res = TEE_SUCCESS;
    uint64_t   cnt_a, cnt_b;
    if( len == 0 ) {
        return res; 
    }

    cnt_a = read_cntpct();
    res = TEE_SimpleRecvConnection( fd, buf, *len, len );
    cnt_b = read_cntpct();
    timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
    if( *len == 0 ) {
        do_close_connection( fd );
    }

    /* For now, we crash the program if errors are encountered.
     * This may change as we build out the network protocol
     */ 
    if( *len < 0 || res != TEE_SUCCESS ) {
        CHECK_SUCCESS( res, "TEE_SimpleRecvConnection error" );
    }

    return res;
}

TEE_Result do_send_connection( int fd, void *buf, int *len ) {
    TEE_Result res = TEE_SUCCESS;
    int        orig_len = *len;
    uint64_t   cnt_a, cnt_b;

    if( len == 0 ) {
        return res;
    }
    
    cnt_a = read_cntpct();
    res = TEE_SimpleSendConnection( fd, buf, *len, len );
    cnt_b = read_cntpct();
    timestamps[curr_ts].rpc_calls += cnt_b - cnt_a;
    if( *len < orig_len ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "do_send_connection() sent only %d/%d B",
                            *len, orig_len );
    }

    if( *len == 0 ) {
        do_close_connection( fd );
    }

    /* For now, we crash the program if errors are encountered.
     * This may change as we build out the network protocol. We
     * operate using client->server model. So server should never
     * be the first to close a connection, unless something 
     * went wrong (connection broken or header/payload was 
     * incorrect ).
     */ 
    if( *len <= 0 || res != TEE_SUCCESS ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "do_send_connection() connection error" );
    }
    
    return res;
}


TEE_Result do_send( int fd, void *buf, size_t len, int op_code, int rv ){
    
    TEE_Result res = TEE_SUCCESS;
    uint8_t    header[HEADER_SIZE];
    size_t     hlen = HEADER_SIZE;
    size_t     plen = len;
    char* device_id = "";
    msgReqHeader msg = {0};

    //MSG( "hdr_len %d B", hdr_len );

    res = serialize_hdr( symm_id, op_code, plen, device_id, 0, &msg );
    CHECK_SUCCESS( res, "serialize_hdr() failed" );

    if ( sizeof(msgReqHeader) >= hlen ) {
        res = TEE_ERROR_SHORT_BUFFER;
        CHECK_SUCCESS( res, "msgReqHeader is larger than HEADER_SIZE" );
    }

    TEE_MemMove( header, &msg, sizeof( msgReqHeader ) );

    //MSG( "header decrypted: %02x%02x%02x%02x %02x%02x%02x%02x", 
    //    header[0], header[1], header[2], header[3],
    //        header[48], header[49], header[50], header[51] );
    
    res = process_aes_block( header, hlen, header, &hlen, ivDefault, sizeof(ivDefault), 0, true, true, encrypt_op );

    CHECK_SUCCESS( res, "process_aes_block() of serialized header failed." );

    //MSG( "header encrypted: %02x%02x%02x%02x %02x%02x%02x%02x", 
    //    header[0], header[1], header[2], header[3],
    //    header[48], header[49], header[50], header[51] );

    res = do_send_connection( fd, header, &hlen );
    CHECK_SUCCESS( res, "do_send_connection() header failed" ); 

    //MSG( "payload: %s len %d", (char*) buf, *len );
    if( plen > 0 ) {
	size_t payload_msg_size = sizeof(msgPayload) + plen;
	unsigned char* payload_msg = TEE_Malloc(payload_msg_size, 0);
	res = serialize_payload(msg.nonce, buf, plen, payload_msg, &payload_msg_size);
	CHECK_SUCCESS( res, "serialize_payload() failed" );

	res = process_aes_block( payload_msg, payload_msg_size, payload_msg, &payload_msg_size, ivDefault, sizeof(ivDefault), 0, true, true, encrypt_op);
	CHECK_SUCCESS( res, "process_aes_block() of serialized payload failed." );

        res = do_send_connection( fd, payload_msg, &payload_msg_size );
        CHECK_SUCCESS( res, "do_send_connection() payload failed" );    
    }

    return res;
}

TEE_Result do_recv_payload( int fd, void* hash, int hlen, 
                            void* buf, int len ) {
    
    TEE_Result    res = TEE_SUCCESS;
    int           nr = len;
    int           read = 0;
    size_t        plen = len;
    unsigned char hash_p[HASHLEN];

    do {
        res = do_recv_connection( fd, ( (char*) buf ) + read, &nr );
        CHECK_SUCCESS( res, "do_recv_connection() failed" );    
        read += nr;
        nr = len - read;
    } while( read < len && nr > 0 );

    process_aes_block( buf, plen, buf, &plen, symm_iv, 
                       symm_iv_len, 0, true, true, decrypt_op );
    
    res = hash_block( buf, read, hash_p, hlen, true, hash_op );
    CHECK_SUCCESS( res, "hash_block() error" );

    if( !compare_hashes( hash, hash_p, HASHLEN ) ) {
        res = TEE_ERROR_COMMUNICATION;
        CHECK_SUCCESS( res, "compare_hashes() header hash does not"
                            " match the hash of the payload" );
    }

    return res;
}

TEE_Result do_recv_header( int fd, msgReplyHeader *msg ) {
    
    TEE_Result  res = TEE_SUCCESS;
    uint8_t     header[HEADER_SIZE];
    int         nr = HEADER_SIZE;
    size_t      hlen = HEADER_SIZE;
    int         read = 0;

    MSG( "Getting the response header..." );

    do {
        res = do_recv_connection( fd, header + read, &nr );
        CHECK_SUCCESS( res, "do_recv_connection() failed" );
        read += nr;
        nr = HEADER_SIZE - read;
    } while( read < HEADER_SIZE && nr > 0 );

    process_aes_block( header, hlen, header, &hlen, symm_iv, 
                       symm_iv_len, 0, true, true, decrypt_op );

    if ( hlen > sizeof( msgReplyHeader ) ) {
        res = TEE_ERROR_SHORT_BUFFER;
        CHECK_SUCCESS( res, "HEADER_SIZE is greater than msgReplayHeader" );
    }

    // Should just be able to shove the bytes into the struct and everything *should* line up....
    TEE_MemMove( msg, header, hlen );
    // deserialize_hdr( msg, header, HEADER_SIZE );
    // if( msg == NULL ) {
    //    res = TEE_ERROR_NOT_SUPPORTED;
    //    CHECK_SUCCESS( res, "deserialize() failed" );
    //}

    if( msg->capsuleID != (int) symm_id ) {
        res = TEE_ERROR_CORRUPT_OBJECT;
        CHECK_SUCCESS( res, "received message for capsule id 0x%08x"
                            " (this capsule id 0x%08x)", 
                            msg->capsuleID, symm_id );
    }

    return res;     
}

/* Search the KV store and write a value to a key. If it doesn't
 * exist, add it.
 */
TEE_Result do_set_capsule_state( unsigned char* key, uint32_t klen, 
                                 unsigned char* val, uint32_t vlen ) {

    TEE_Result res = TEE_SUCCESS;
    uint32_t count;
    kv_pair *lookup_result, *new_entry = NULL;

    //Do size check for the key and value.
    if (vlen > STATE_SIZE || klen > STATE_SIZE)
    {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS(res, "val/key buffer %u/%u B too large"
                           "(need to be less than %u B",
                      vlen, klen, STATE_SIZE);
    }

    //Assign values to the new entry.
    new_entry->key = key;
    new_entry->value = val;
    new_entry->key_len = klen;
    new_entry->val_len = vlen;

    //hashtable lookup for the key
    HASH_FIND_PTR(cap_head.kv_store, key, lookup_result);
    if (lookup_result == NULL)
    {
        HASH_ADD_KEYPTR(hh, cap_head.kv_store, new_entry->key, new_entry->key_len, new_entry);
    }
    else
    {
        HASH_REPLACE_PTR(cap_head.kv_store, key, new_entry, lookup_result); //Convenience Macro. This should work.
        //HASH_REPLACE(hh,cap.kv_store, new_entry->key,new_entry->key_len, new_entry, lookup_result);
    }
    return res;
}

TEE_Result do_get_capsule_state(unsigned char *key, unsigned char *val,
                                uint32_t vlen)
{
    TEE_Result res = TEE_SUCCESS;
    kv_pair *lookup_result = NULL;

    if (vlen < STATE_SIZE)
    {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS(res, "val buffer %u B too small"
                           "(need to be larger than %u B",
                      vlen, STATE_SIZE);
    }
    
    HASH_FIND_PTR(cap_head.kv_store, key, lookup_result);

    if (lookup_result == NULL)
    {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        CHECK_SUCCESS(res, "key %s not found", key);
    }
    strncpy(val, lookup_result->value, lookup_result->val_len);
    return res;
}

TEE_Result do_append_blacklist(const char* key, size_t keyLen, const WHERE w)
{
    TEE_Result res = TEE_SUCCESS;
    kv_pair *black_list_name, *lookup_result, *new_entry = NULL;
    size_t *size;

    switch( w ) {
    //case BL_TRUSTED_APP:
    //	return NIL;
    case BL_SECURE_STORAGE:
    	black_list_name = cap_head.secure_storage_bl;
        size = &cap_head.secure_storage_bl_len;
    case BL_CAPSULE_META:
    	black_list_name = cap_head.metadata_bl;
        size = &cap_head.metadata_bl_len;
    default:
    	return ERROR_APPEND_BLACKLIST;
    }
    //0. Prepare the new blacklist entry. 
    new_entry -> key = key;
    new_entry -> key_len = (uint32_t) keyLen;
    new_entry -> value = NULL;
    new_entry -> value = 0;

    //1. Search for key and add to the respective hashtable.
    HASH_FIND_PTR(black_list_name, key, lookup_result);
    if (lookup_result == NULL)
    {
        HASH_ADD_KEYPTR(hh, black_list_name, new_entry->key, new_entry->key_len, new_entry);
    }
    else
    {
        HASH_REPLACE_PTR(black_list_name, key, new_entry, lookup_result); //Convenience Macro. This should work.
        //HASH_REPLACE(hh,cap.kv_store, new_entry->key,new_entry->key_len, new_entry, lookup_result);
    }

    //2. Increase the hashthable entry count.
    (*size)++;
    return res;
}


TEE_Result do_remove_from_blacklist(const char *key, size_t keyLen, const WHERE w)
{
    TEE_Result res = TEE_SUCCESS;
    kv_pair *black_list_name, *lookup_result, *new_entry = NULL;
    size_t *size;

    switch (w)
    {
    //case BL_TRUSTED_APP:
    //	return NIL;
    case BL_SECURE_STORAGE:
        black_list_name = cap_head.secure_storage_bl;
        size = &cap_head.secure_storage_bl_len;
    case BL_CAPSULE_META:
        black_list_name = cap_head.metadata_bl;
        size = &cap_head.metadata_bl_len;
    default:
        return ERROR_REMOVE_BLACKLIST;
    }
    
    //1. Search for key and add to the respective hashtable.
    HASH_FIND_PTR(black_list_name, key, lookup_result);
    if (lookup_result == NULL)
    {
        return res; // The key doesn't exist. Life's simple. 
    }
    else
    {
        HASH_DEL(black_list_name, lookup_result);
    }

    //2. Increase the hashthable entry count.
    (*size)--;
    return res;
}

/* Format: KEY size -> 128 B 
 *         VALUE size -> 128 B
 *      KEY1 VALUE1 VALID/INVALID
 *      KEY2 VALUE2 VALID/INVALID
 *      ...
 */

/* Search the stateFile and write the value to a key. If it does not exist,
 * append to the end of the state file or next available */
TEE_Result
do_set_state(unsigned char *key, uint32_t klen,
             unsigned char *val, uint32_t vlen)
{

    TEE_Result res = TEE_SUCCESS;
    uint32_t   count;
    uint8_t    state[2*STATE_SIZE + 1];
    uint8_t   *key_state = &state[0];
    uint8_t   *val_state = &state[STATE_SIZE];
    uint8_t   *valid = &state[2*STATE_SIZE];
    uint32_t   write_off = 0;
    uint32_t   new_write_pos = 0;
    uint64_t   cnt_a, cnt_b;

    DMSG( "Setting key: %s val: %s", key, val );

    if( vlen > STATE_SIZE || klen > STATE_SIZE ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "val/key buffer %u/%u B too large"
                            "(need to be less than %u B", 
                            vlen, klen, STATE_SIZE );
    }

    cnt_a = read_cntpct();
    res = TEE_SeekObjectData( stateFile, 0, TEE_DATA_SEEK_SET );
    cnt_b = read_cntpct();
    timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
    CHECK_SUCCESS( res, "TEE_SeekObjectData() Error" );

    /* First check to see if this state already exists */
    while( 1 ) {
        cnt_a = read_cntpct();
        res = TEE_ReadObjectData( stateFile, state, sizeof(state), &count ); 
        cnt_b = read_cntpct();
        timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
        CHECK_SUCCESS( res, "TEE_ReadObjectData Error" );

        if( count == 0 ) {
            new_write_pos = write_off * ( sizeof(state) );      
            //MSG( "Writing to end of file %u", new_write_pos );
            break;
        }
    
        if( strcmp( (const char*) key, (const char*) key_state ) == 0 ) {
            new_write_pos = write_off * ( sizeof(state) );
            //MSG( "Writing to offset %u, key found", new_write_pos );
            break;
        }
        
        if( new_write_pos == 0 && *valid == 0 ) {
            new_write_pos = write_off * ( sizeof(state) );
            //MSG( "Write to first invalid entry %u", new_write_pos );
        }

        write_off++;
    }

    /*  Add the state in at the first available slot */
    memset( state, 0, sizeof(state) );
    memcpy( key_state, key, klen );
    memcpy( val_state, val, vlen );
    *valid = 1;

    cnt_a = read_cntpct();
    res = TEE_SeekObjectData( stateFile, new_write_pos, TEE_DATA_SEEK_SET );
    res = TEE_WriteObjectData( stateFile, state, sizeof(state) );
    cnt_b = read_cntpct();
    timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
    CHECK_SUCCESS( res, "TEE_WriteObjectData Error" );

    return res;
}

TEE_Result do_get_state( unsigned char* key, unsigned char* val, 
                         uint32_t vlen ) {
    TEE_Result res = TEE_SUCCESS;
    uint32_t   count;
    bool       found = false;
    uint8_t    state[2*STATE_SIZE+1];
    uint8_t   *key_state = &state[0];
    uint8_t   *val_state = &state[STATE_SIZE];
    uint8_t   *valid = &state[2*STATE_SIZE];
    uint64_t   cnt_a, cnt_b;

    DMSG( "Looking for key: %s", key );

    if( vlen < STATE_SIZE ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "val buffer %u B too small" 
                            "(need to be larger than %u B", 
                            vlen, STATE_SIZE );
    }

    cnt_a = read_cntpct();
    res = TEE_SeekObjectData( stateFile, 0, TEE_DATA_SEEK_SET );
    cnt_b = read_cntpct();
    timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
    CHECK_SUCCESS( res, "TEE_SeekObjectData() Error" );

    while( 1 ) {
        cnt_a = read_cntpct();
        res = TEE_ReadObjectData( stateFile, state, 2*STATE_SIZE+1, &count );
        cnt_b = read_cntpct();
        timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
        CHECK_SUCCESS( res, "TEE_ReadObjectData Error" );

        if( count == 0 ) break;
        if( strcmp( (const char*) key, (const char*) key_state ) == 0 
            && *valid != 0 ) {
            found = true;
            memcpy( val, val_state, STATE_SIZE );
            break;
        }
    }

    if( found == false ) {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        CHECK_SUCCESS( res, "key %s not found", key );
    }
    return res; 
}

/*
TEE_Result go_get_device_state(unsigned char *key, unsigned char *val,
                               uint32_t vlen) 
{
    TEE_Result res = TEE_SUCCESS;
    uint32_t count;
    bool found = false;
    uint8_t state[2 * STATE_SIZE + 1];
    uint8_t *key_state = &state[0];
    uint8_t *val_state = &state[STATE_SIZE];
    uint8_t *valid = &state[2 * STATE_SIZE];
    uint64_t cnt_a, cnt_b;

    DMSG("Looking for key: %s in device file", key);

    if (vlen < STATE_SIZE)
    {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS(res, "val buffer %u B too small"
                           "(need to be larger than %u B",
                      vlen, STATE_SIZE);
    }

    cnt_a = read_cntpct();
    res = TEE_SeekObjectData(deviceFile, 0, TEE_DATA_SEEK_SET);
    cnt_b = read_cntpct();
    timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
    CHECK_SUCCESS(res, "TEE_SeekObjectData() Error");

    while (1)
    {
        cnt_a = read_cntpct();
        res = TEE_ReadObjectData(deviceFile, state, 2 * STATE_SIZE + 1, &count);
        cnt_b = read_cntpct();
        timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
        CHECK_SUCCESS(res, "TEE_ReadObjectData Error");

        if (count == 0)
            break;
        if (strcmp((const char *)key, (const char *)key_state) == 0 && *valid != 0)
        {
            found = true;
            memcpy(val, val_state, STATE_SIZE);
            break;
        }
    }

    if (found == false)
    {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        CHECK_SUCCESS(res, "key %s not found", key);
    }
    return res;
}
*/
char *
do_get_buffer(BUF_TYPE t, size_t *len, TEE_Result *res)
{
    char* buffer;

    *res = TEE_SUCCESS;

    switch(t) {
        case POLICY:
            buffer = TEE_Malloc(cap_head.policy_len, 0);
            TEE_MemMove(buffer, cap_head.policy_buf, cap_head.policy_len);
            *len = cap_head.policy_len;
            return buffer;
        case KV_STRING:
             // Get length of KV string
            *len = get_kv_string_len();
            buffer = TEE_Malloc(*len, 0);
            serialize_kv_store((unsigned char*)buffer, *len);
            // buffer[*len] = '\0';
            return buffer;
        case LOG:
            buffer = TEE_Malloc(cap_head.log_len + 1, 0);
            TEE_MemMove(buffer, cap_head.log_buf, cap_head.log_len);
            // buffer[cap_head.log_len] = '\0';
            *len = cap_head.log_len;
            return buffer;
        case DATA:
            buffer = TEE_Malloc(cap_head.data_len + 1, 0);
            TEE_MemMove(buffer, cap_head.data_buf, cap_head.data_len);
            // buffer[cap_head.data_len] = '\0';
            *len = cap_head.data_len;
            return buffer;
        case DATA_SHADOW:
            buffer = TEE_Malloc(cap_head.data_shadow_len + 1, 0);
            TEE_MemMove(buffer, cap_head.data_shadow_buf, cap_head.data_shadow_len);
            // buffer[cap_head.data_shadow_len] = '\0';
            *len = cap_head.data_shadow_len;
            return buffer;
        default:
            *res = TEE_ERROR_NOT_SUPPORTED;
            return NULL;
    }
}

TEE_Result do_redact(char *buf, char **newBuf, char *replaceString, size_t start, size_t end, size_t len)
{
    TEE_Result res = TEE_SUCCESS;
    int MAX_SIZE;
    if (len <= (end - start))
    {
        MAX_SIZE = strlen(buf);
    }
    else
    {
        MAX_SIZE = strlen(buf) + len - end + start;
    }
    char *newString = TEE_Malloc(sizeof(char) * MAX_SIZE,0);
    int i = 0;
    while (i < start)
    {
        newString[i] = buf[i];
        i++;
    }
    i = 0;
    while (i < len)
    {
        newString[i + start] = replaceString[i];
        i++;
    }
    int j = 0;
    i--;
    while (buf[end + j] != '\0')
    {
        newString[start + i] = buf[end + j];
        i++;
        j++;
    }
    
    *newBuf = TEE_Malloc(sizeof(char) * strlen(newString),0);
    TEE_MemMove(*newBuf, newString, strlen(newString));
    return res;
    //TODO: errors
}