#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>
#include <stdlib.h>
#include <string.h>
#include <capsule.h>
#include <amessage.pb-c.h>
#include <serialize_common.h>
#include <lua.h>
#include "capsule_structures.h"
#include "capsule_helper.h"
#include "capsule_op.h"
#include "capsule_ta.h"

// TODO: remove chunksize
TEE_Result do_register_aes( uint32_t keyType, uint32_t id, 
                            uint32_t chSize, uint32_t keyLen, 
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
     * => Total size, ch size, key size, key id, iv size, iv, attrs 
     */
    if( keyFile != TEE_HANDLE_NULL ) {

        res = TEE_SeekObjectData( keyFile, 0, TEE_DATA_SEEK_END );
        CHECK_SUCCESS( res, "TEE_SeekObjectData() Error" );
        
        // Should be 4 instead of 5. (remove chunk size)
        total_size = attrlen + ivlen + 5*sizeof(uint32_t);
        
        MSG( "Write %u B of AES key 0x%08x to sec. storage",
             total_size, id );

        data_buffer = TEE_Malloc( total_size, 0 );
        it = data_buffer;

        //total_size less size of total_size 
        *(uint32_t*) (void*) it = total_size - sizeof(uint32_t);
        //MSG( "First 4 bytes: %u", *(uint32_t*)(void*) it );       
        it += sizeof(uint32_t);

        //chunk_size -- REMOVE
        *(uint32_t*) (void*) it = chSize;
        //MSG( "Second 4 bytes: %u", *(uint32_t*)(void*) it );
        it += sizeof(uint32_t);

        //key_len
        *(uint32_t*) (void*) it = keyLen;                
        //MSG( "Second 4 bytes: %u", *(uint32_t*)(void*) it );       
        it += sizeof(uint32_t);
        //key_id
        *(uint32_t*) (void*) it = id;               
        //MSG( "Third 4 bytes: %08x", *(uint32_t*)(void*) it );    
        it += sizeof(uint32_t);
        //iv_size
        *(uint32_t*) (void*) it = ivlen;            
        //MSG( "Fourth 4 bytes: %u", *(uint32_t*)(void*) it );      
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
    unsigned char       ptx[file_size]; // The largest the plaintext will be
    size_t              ptxlen = file_size;
    int                 init_ctr = 0;

    // Initialize the capsule's text index structure and header if this is the first
    // open call. Otherwise, everything is already loaded and we do nothing.
    if( cap_head.ref_count == 0 ) {
        initialize_capsule_text( &cap_head );

        read_header(file_contents, &header);

        if( aes_key_setup == false ) {
            res = find_key( &header, keyFile, &decrypt_op, &encrypt_op,
                            &hash_op, &symm_id, &symm_iv_len, &symm_key_len,
                            &symm_chunk_size, &symm_iv );
            CHECK_SUCCESS( res, "Find_key() Error" );   
            aes_key_setup = true;
        }

        // MSG("Copying header (size %d)", sizeof(struct TrustedCap));
        cap_head.header = header;
        
        // MSG("Decrypt the file");
        // Decrypt the entire file (starting after the header)
        res = process_aes_block(file_contents + sizeof(struct TrustedCap), 
                                file_size - sizeof(struct TrustedCap), ptx, 
                                &ptxlen, symm_iv, symm_iv_len, 
                                init_ctr, true, true, decrypt_op);

        ptx[ptxlen] = '\0';

        // Parse out the file into specific buffers. Requires one pass to find all the
        // delimiters. Start at the end of the header. 
        // MSG("Separate the parts [%d], strlen [%d]", ptxlen, strlen((char*) ptx));
        sep_parts(ptx, ptxlen, &cap_head);
    }

    // MSG("returning");
    return res;
}

unsigned char* do_close( TEE_Result policy_res, size_t *new_len, 
                         bool flush_flag ) {
    TEE_Result      res = TEE_SUCCESS;
    unsigned char  *unencrypted, *encrypted_file, *encrypted_data, *data, *kvstore;
    size_t          datalen, 
                    encrypt_len,
                    kv_len,
                    plt_len,
                    total_len = 0,
                    hlen = HASH_LEN;
    int             last = 0, 
                    init_ctr = 0;
    unsigned char   hash[HASH_LEN];

    if (policy_res != TEE_SUCCESS) {
        // Use data buffer
        data = cap_head.data_buf;
        datalen = cap_head.data_len;
    } else {
        data = cap_head.data_shadow_buf;
        datalen = cap_head.data_shadow_len;
    }

    // Figure out how large to make the buffer
    // MSG("Calculate length");
    for (unsigned int i = 0; i < cap_head.kv_store_len; i++) {
        total_len += cap_head.kv_store_buf[i].key_len + 1; // Key + :
        total_len += cap_head.kv_store_buf[i].val_len + 1; // Val + ;
    }

    // MSG("KV string remalloc with length: %d", total_len);
    kvstore = TEE_Malloc(total_len, 0);

    // MSG("Serialize kv store: %p", kvstore);
    serialize_kv_store(kvstore, total_len);
    // MSG("done serialize kv store %p", kvstore);

    // Calculate lengths
    kv_len = strlen( (char*) kvstore);
    encrypt_len = cap_head.policy_len + cap_head.log_len + 
                  kv_len + datalen + DELIMITER_SIZE*3 - 3;
    plt_len = sizeof(cap_head.header);
    *new_len = encrypt_len + plt_len;
    // MSG("Lengths (%u, %u, %u)", encrypt_len, plt_len, *new_len);


    // Reallocate buffer to fit new file (contains plaintext header and 
    // encrypted data)
    // MSG("Allocating encrypted_file with size %d", *new_len);
    encrypted_file = TEE_Malloc( *new_len, 0 );
    // MSG("encrypted_file %p", encrypted_file);

    // MSG("Allocating unencrypted with size %d", encrypt_len);
    // Allocate buffer to hold encrypted data
    unencrypted = TEE_Malloc( encrypt_len, 0 );
    encrypted_data = TEE_Malloc(encrypt_len, 0);

    // Concatenate all the buffers for encryption
    // MSG("Moving %d of policy to %d", cap_head.policy_len - 1, last);
    TEE_MemMove(unencrypted, cap_head.policy_buf, cap_head.policy_len - 1);
    last += cap_head.policy_len - 1;
    // MSG("Moving %d of delimiter to %d", DELIMITER_SIZE, last);
    TEE_MemMove(unencrypted + last, DELIMITER, DELIMITER_SIZE);
    last += DELIMITER_SIZE;
    // MSG("Moving %d of kv store to %d", kv_len - 1, last);
    TEE_MemMove(unencrypted + last, kvstore, kv_len - 1);
    last += kv_len - 1;
    // MSG("Moving %d of delimiter to %d", DELIMITER_SIZE, last);
    TEE_MemMove(unencrypted + last, DELIMITER, DELIMITER_SIZE);
    last += DELIMITER_SIZE;
    // MSG("Moving %d of log to %d", cap_head.log_len - 1, last);
    TEE_MemMove(unencrypted + last, cap_head.log_buf, cap_head.log_len - 1);
    last += cap_head.log_len - 1;
    // MSG("Moving %d of delimiter to %d", DELIMITER_SIZE, last);
    TEE_MemMove(unencrypted + last, DELIMITER, DELIMITER_SIZE);
    last += DELIMITER_SIZE;
    // MSG("Moving %d of data to %d", datalen, last);
    TEE_MemMove(unencrypted + last, data, datalen);
    last += datalen;

    unencrypted[last] = '\0';

    // MSG("end size: %d", last);
    // MSG("Log: %s", cap_head.log_buf);
    // MSG("strlen(log): %d, log_len: %d", strlen(cap_head.log_buf), cap_head.log_len);

    // MSG("Unencrypted data: %s", unencrypted + datastart);

    // Encrypt the data into the file (leaving room for the header)
    // MSG("Encrypt data (%u, %lu, %d)", symm_iv, symm_iv_len, init_ctr);
    res = process_aes_block(unencrypted, encrypt_len, encrypted_data, 
                            &encrypt_len, symm_iv, symm_iv_len, init_ctr, true,
                            true, encrypt_op);

    // TODO: add error handling
    // Update header hash values and size
    // MSG("Hash everything");
    res = hash_block(encrypted_data, encrypt_len, hash, hlen, true, hash_op);
    if( res != TEE_SUCCESS ) {
        MSG( "hash_block() Error" );
        return NULL;
    }

    for (unsigned int i = 0; i < hlen; i++) {
        if (cap_head.header.hash[i] != hash[i]) {
            MSG("%d: %02x != %02x", i, cap_head.header.hash[i], hash[i]);
        }
    }

    TEE_MemMove(&cap_head.header.hash, hash, hlen);


    // Fill in the new header
    // MSG("Fill header");
    res = fill_header(&cap_head.header, encrypt_op, symm_iv, symm_iv_len, 
                      symm_id, hash, hlen, encrypt_len);

    // Copy header over
    // MSG("Copy header");
    TEE_MemMove(encrypted_file, &cap_head.header, plt_len);

    // MSG("Copying encrypted data");
    TEE_MemMove(encrypted_file + plt_len, encrypted_data, encrypt_len);

    if( res != TEE_SUCCESS ) {
        MSG( "process_aes_block() Error" );
        return NULL;
    }

    if (!flush_flag) {
        // If we are not just flushing, decrease the reference count
        cap_head.ref_count--;
    }

    if (cap_head.ref_count == 0) {
        // Clear out the buffers if this is the last reference to the capsule
        finalize_capsule_text(&cap_head);
    }

    // MSG("Free kvstore");
    // TEE_Free(kvstore);

    // MSG("returning");
    return encrypted_file;
}

/* Run the Lua policy function - if the policy was changed,
 *                               run it again */
TEE_Result do_run_policy( lua_State *L, const char* policy, SYSCALL_OP n ) { 

    int  res = TEE_SUCCESS, ret = LUA_OK;
    int  cur_stack = lua_gettop(L);
    bool eval, pol_changed;
    uint64_t cnt_a, cnt_b;

    // MSG("Running policy");

    cnt_a = read_cntpct();
    do {
        /* Call lua policy function */
        lua_getglobal( L, policy );
        lua_pushnumber( L, n ); /* policy takes a number argument */
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
        //MSG( "Function '%s:%d' pol_changed is %s", policy, n,
        //   pol_changed == true ? "true" : "false" );
        
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
    // MSG( "Function '%s:%d' evaluated to %s", policy, n,
    //   eval == true ? "true" : "false" );
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
    // MSG("Loading policy [%s]", cap_head.policy_buf);
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

    // If the new length is not the same as the current len, then resize the buffer
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

    
TEE_Result do_send( int fd, void *buf, int *len, int op_code, int rv ){
    
    TEE_Result res = TEE_SUCCESS;
    uint8_t    header[HEADER_SIZE];
    int        hdr_len = HEADER_SIZE;
    size_t     hlen = HEADER_SIZE;
    size_t     plen = *len;

    //MSG( "hdr_len %d B", hdr_len );

    serialize_hdr( symm_id, op_code, buf, *len, rv, curr_cred,
                   header, hdr_len );   
    
    //MSG( "header decrypted: %02x%02x%02x%02x %02x%02x%02x%02x", 
    //    header[0], header[1], header[2], header[3],
    //        header[48], header[49], header[50], header[51] );
    
    process_aes_block( header, hlen, header, &hlen, symm_iv, 
                       symm_iv_len, 0, true, true, encrypt_op );

    //MSG( "header encrypted: %02x%02x%02x%02x %02x%02x%02x%02x", 
    //    header[0], header[1], header[2], header[3],
    //    header[48], header[49], header[50], header[51] );


    res = do_send_connection( fd, header, &hdr_len );
    CHECK_SUCCESS( res, "do_send_connection() header failed" ); 

    //MSG( "payload: %s len %d", (char*) buf, *len );
    if( *len > 0 ) {
        process_aes_block( buf, plen, buf, &plen, symm_iv, symm_iv_len,
                           0, true, true, encrypt_op );

        res = do_send_connection( fd, buf, len );
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
    unsigned char hash_p[HASH_LEN];

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

    if( !compare_hashes( hash, hash_p, HASH_LEN ) ) {
        res = TEE_ERROR_COMMUNICATION;
        CHECK_SUCCESS( res, "compare_hashes() header hash does not"
                            " match the hash of the payload" );
    }

    return res;
}

TEE_Result do_recv_header( int fd, AMessage **msg ) {
    
    TEE_Result  res = TEE_SUCCESS;
    uint8_t     header[HEADER_SIZE];
    int         nr = HEADER_SIZE;
    size_t      hlen = HEADER_SIZE;
    int         read = 0;

    //MSG( "Getting the response header..." );

    do {
        res = do_recv_connection( fd, header + read, &nr );
        CHECK_SUCCESS( res, "do_recv_connection() failed" );
        read += nr;
        nr = HEADER_SIZE - read;
    } while( read < HEADER_SIZE && nr > 0 );

    process_aes_block( header, hlen, header, &hlen, symm_iv, 
                       symm_iv_len, 0, true, true, decrypt_op );

    deserialize_hdr( msg, header, HEADER_SIZE );
    if( *msg == NULL ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "deserialize() failed" );
    }

    if( (*msg)->tz_id != curr_cred || (*msg)->capsule_id != (int) symm_id ) {
        res = TEE_ERROR_CORRUPT_OBJECT;
        CHECK_SUCCESS( res, "received message for TZ id 0x%08x capsule id 0x%08x"
                            " (this TZ id is 0x%08x capsule id 0x%08x)", 
                            (*msg)->tz_id, curr_cred, (*msg)->capsule_id, symm_id );
    }

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
TEE_Result do_set_state( unsigned char* key, uint32_t klen, 
                         unsigned char* val, uint32_t vlen ) {

    TEE_Result res = TEE_SUCCESS;
    uint32_t   count;
    uint8_t    state[2*STATE_SIZE + 1];
    uint8_t   *key_state = &state[0];
    uint8_t   *val_state = &state[STATE_SIZE];
    uint8_t   *valid = &state[2*STATE_SIZE];
    uint32_t   write_off = 0;
    uint32_t   new_write_pos = 0;
    uint64_t   cnt_a, cnt_b;

    //MSG( "Setting key: %s val: %s", key, val );

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

    //MSG( "Looking for key: %s", key );

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