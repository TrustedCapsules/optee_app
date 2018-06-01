#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <capsuleCommon.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "capsule_ta.h"
#include "capsule_lua_ext.h"
#include "capsule_structures.h"
#include "capsule_helper.h"


unsigned long long read_cntpct(void) {
    unsigned long long ts;
//#ifdef HIKEY
//  asm volatile( "mrs %0, cntpct_el0" : "=r" (ts) );
//#else
    asm volatile( "mrrc p15, 0, %Q0, %R0, c14" : "=r" (ts) );
//#endif
    return ts;
}


int getfield( lua_State *L, int key, int tindex ) {
    int result;
    lua_geti( L, tindex, key ); /* Pops key, puts t[key] */
    if( !lua_isinteger( L, -1 ) ) 
        luaL_error( L, "Redact array must be integers" );
    result = lua_tointeger( L, -1 );
    lua_pop( L, 1 ); /* Remove number */
    return result;
}


// TEE_Result lua_read_redact( lua_State *L, int state_tgid, int state_fd,
//                          unsigned char *bp, uint32_t len ) {

//  int                      cur_stack = lua_gettop( L );
//  int                      start, end, table, table_start, table_end;
//  unsigned int             i;
//  char                     replace_char[2];
//  TEE_Result               res = TEE_SUCCESS;
//  struct cap_text_entry   *cap_entry;

//  /* Default replacement character */
//  replace_char[0] = ' ';
//  replace_char[1] = '\0';

//  res = lua_get_replacement_char( L, replace_char );
//  CHECK_SUCCESS( res, "lua_get_replacement_char() error" );

//  lua_getglobal( L, REDACT_OFFSETS );

//  if( !lua_isnil( L, -1 ) ) {
//      if( !lua_istable( Lstate, -1 ) ) {
//          res = TEE_ERROR_NOT_SUPPORTED;
//          CHECK_SUCCESS( res, "'%s' should be a table", REDACT_OFFSETS );
//      }

//      table = lua_gettop( L );

//      cap_entry = find_capsule_entry( &cap_head.proc_entries, state_tgid, state_fd );
//      if( cap_entry == NULL ) {
//          res = TEE_ERROR_NOT_SUPPORTED;
//          CHECK_SUCCESS( res, "find_capsule_entry() -> tgid/fd %d/%d not found", 
//                         state_tgid, state_fd );  
//      }

//      start = cap_entry->data_pos - cap_head.data_begin - len;
//      end = cap_entry->data_pos - cap_head.data_begin;

//      // MSG( "start: %d, end: %d", start, end );

//      for( i = 1; i <= lua_rawlen( L, table ); i=i+2 ) {
//          table_start = getfield( L, i, table );
//          table_end = getfield( L, i+1, table );
//          // MSG( "table_start: %d, table_end: %d", table_start, table_end );
    
//          if( start > table_start && end > table_end && table_end >= start ) {    
//               <------------>
//              *        <----------------------------> 
//              memset( bp, replace_char[0], table_end - start + 1 );
//          } else if( table_start > start && table_end > end && end >= table_start ) {
//              /*                                <------------>
//              *       <----------------------------> */
//              memset( bp + table_start - start, replace_char[0], end - table_start + 1);
//              break;
//          } else if( table_start >= start && table_end <= end ) {
//              /*                 <-------->
//              *       <-----------------------------> */
//              memset( bp + table_start - start, replace_char[0], table_end - table_start + 1 ); 
//          } else if( table_start < start && table_end > end ) {
//              /*  <------------------------------------------>
//              *       <-----------------------------> */
//              memset( bp, replace_char[0], len );
//              break;
//          }
//          /* <-->
//           *        <----------------------------> */ 
        
//          /*                                        <---->
//           *        <----------------------------> */
//      }
//  }

//  lua_settop( L, cur_stack );

//  return res;
// }

// TEE_Result lua_get_replacement_char( lua_State *L, char* replace ) {
//     int res = TEE_SUCCESS;
//     const char* temp;
//     size_t len;

//     lua_getglobal( L, REPLACE_CHAR );
//     if ( !lua_isstring( L, -1 ) ) {
//         res = TEE_ERROR_NOT_SUPPORTED;
//         CHECK_SUCCESS( res, "'%s' should be a string", REPLACE_CHAR );
//     }

//     temp = lua_tolstring( L, -1, &len );
//     memcpy( replace, temp, len );

//     lua_pop( L, 1);

//     return TEE_SUCCESS;
// }

/* Get the secure server address */
TEE_Result lua_get_server_ip_port( lua_State *L, char* ts, int* port ) {

    int res = TEE_SUCCESS;  
    const char* temp;
    size_t      len;

    lua_getglobal( L, SERVER_IP );
    if( !lua_isstring( L, -1 ) ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "'%s' should be a string", SERVER_IP );
    }

    temp = lua_tolstring( L, -1, &len );
    memcpy( ts, temp, len );
    lua_pop( L, 1 );

    lua_getglobal( L, SERVER_PORT );
    if( !lua_isinteger( L, -1 ) ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "'%s' should be an integer", SERVER_PORT );
    }

    *port = lua_tointeger( L, -1 );
    lua_pop( L, 1 );

    return TEE_SUCCESS;
}

/* Load a policy file into Lua interpreter */
TEE_Result lua_load_policy( lua_State *L, const char* buf ) {

    int res = TEE_SUCCESS;
    int ret = luaL_loadstring( L, buf ) || 
              lua_pcall( L, 0, 0, 0 );
    if( ret != LUA_OK ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "policy Lua file cannot be run >> error"
                            " code %d", ret );
    }

    return res;
}   

/* Start a new Lua context */
void lua_start_context( lua_State **L ) {
    *L = luaL_newstate();
    luaL_openlibs( *L );
}

/* Close a Lua context */
void lua_close_context( lua_State **L ) {
    if( *L != NULL )
        lua_close( *L );
    *L = NULL;
}

/* Performs encryption and decryption for a piece of data */
TEE_Result process_aes_block( unsigned char* ctx, size_t clen,
                              unsigned char* ptx, size_t *plen,
                              uint8_t *iv, uint32_t iv_len, uint32_t ctr,
                              bool first, bool last,
                              TEE_OperationHandle op ) {
    TEE_Result res = TEE_SUCCESS;
    uint64_t   cnt_a, cnt_b;

    cnt_a = read_cntpct();
    
    if( first ) {
        TEE_CipherInit( op, iv, iv_len, ctr );
    }

    if( last ) {
        res = TEE_CipherDoFinal( op, ctx, clen, ptx, plen );
        CHECK_SUCCESS( res, "TEE_CipherDoFinal() Error" );
    } else {
        res = TEE_CipherUpdate( op, ctx, clen, ptx, plen );
        CHECK_SUCCESS( res, "TEE_CipherUpdate() Error" );
    }

    cnt_b = read_cntpct();

    timestamps[curr_ts].encryption += cnt_b - cnt_a;

    return res;
}

/* Wrapper for network hashing */
TEE_Result hash_data( unsigned char* payload, size_t payload_len,
                      unsigned char* hash, size_t hlen ) {
    return hash_block( payload, payload_len, hash, hlen, 1, hash_op );
}

/* Hashes a block of data */
TEE_Result hash_block( unsigned char* ptx, size_t plen,
                       unsigned char* hash, size_t hlen, 
                       bool last, TEE_OperationHandle op ) {
    
    TEE_Result res = TEE_SUCCESS;
    uint64_t    cnt_a, cnt_b;

    cnt_a = read_cntpct();

    if( hlen != HASH_LEN ) {
        return TEE_ERROR_NOT_SUPPORTED;
    }

    if( last ) {
        res = TEE_DigestDoFinal( op, ptx, plen, hash, &hlen );
        CHECK_SUCCESS( res, "TEE_DigestDoFinal() Error" );
    } else {
        TEE_DigestUpdate( op, ptx, plen );
    }

    cnt_b = read_cntpct();

    timestamps[curr_ts].hashing += cnt_b - cnt_a;

    return res;
}

/* Compare two hashes */
bool compare_hashes( unsigned char* hash1, unsigned char* hash2,
                     size_t hlen ) {
    size_t n;
    for( n = 0; n < hlen; n++ ) {
        if( hash1[n] != hash2[n] ) {
            MSG( "hash1: %02x%02x%02x%02x does not match hash2: %02x%02x%02x%02x", 
                 hash1[0], hash1[1], hash1[2], hash1[3], hash2[0], hash2[1], hash2[2], hash2[3]);
            return false;
        }
    }
    return true;
}

/* Initialize the capsule text buffer */
void initialize_capsule_text( struct capsule_text* p ) {
    memset(&(p->header), 0, sizeof(struct TrustedCap));
    p->policy_len = 0;
    p->log_len = 0;
    p->kv_store_len = 0;
    p->data_len = 0;
    p->ref_count = 0;
}

void finalize_capsule_text( struct capsule_text* p ) {
    p->ref_count = 0;
    memset(&(p->header), 0, sizeof(struct TrustedCap));
    p->policy_len = 0;
    p->log_len = 0;
    p->kv_store_len = 0;
    p->data_len = 0;
    p->data_shadow_len = 0;

    TEE_Free(p->policy_buf);
    TEE_Free(p->log_buf);
    TEE_Free(p->kv_store_buf);
    TEE_Free(p->data_buf);
    TEE_Free(p->data_shadow_buf);
}

/* Check that a key was found */
bool key_not_found( uint8_t *gl_iv, uint32_t gl_id,
                    uint32_t gl_iv_len, uint32_t gl_key_len ) {
    if( gl_iv == NULL || gl_id == 0 || 
        gl_iv_len == 0 || gl_key_len == 0 ) {
        return true;
    }
    return false;
}

/* Find a key for trusted capsule */
TEE_Result find_key( struct TrustedCap *h, 
                     TEE_ObjectHandle file,
                     TEE_OperationHandle *dec_op,
                     TEE_OperationHandle *enc_op,
                     TEE_OperationHandle *sha_op,
                     uint32_t *gl_id, 
                     uint32_t *gl_iv_len,
                     uint32_t *gl_key_len, 
                     uint8_t **gl_iv ) {
    
    TEE_Result       res = TEE_SUCCESS;
    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    TEE_Attribute   *attrs = NULL;
    uint32_t         total_size, count, id, iv_len;
    uint32_t         key_attr_len, key_len;
    uint32_t         attr_count, cap_id;
    uint8_t         *attr_buf = NULL, *it = NULL;
    uint8_t         *iv = NULL, *key_attr = NULL;
    size_t           id_len = 4;    
    uint64_t         cnt_a, cnt_b;

    cnt_a = read_cntpct();
    res = TEE_SeekObjectData( file, 0, TEE_DATA_SEEK_SET );
    cnt_b = read_cntpct();
    timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
    CHECK_SUCCESS( res, "TEE_SeekObjectData() Error" );

    while( 1 ) {
        cnt_a = read_cntpct();  
        res = TEE_ReadObjectData( file, &total_size, 
                                  sizeof(uint32_t), &count );
        cnt_b = read_cntpct();
        timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
        CHECK_GOTO( res, find_key_exit,
                        "TEE_ReadObjectData() Error" );
        if( count == 0 ) { 
            res = TEE_ERROR_NOT_SUPPORTED;
            CHECK_SUCCESS( res, "Find_key() AES key not found" );
            goto find_key_exit;
        }

        attr_buf = TEE_Malloc( total_size, 0 );
        cnt_a = read_cntpct();
        res = TEE_ReadObjectData( file, attr_buf, 
                                  total_size, &count );
        cnt_b = read_cntpct();
        timestamps[curr_ts].secure_storage += cnt_b - cnt_a;
        if( count == 0 ) {
            MSG( "Find_key()-> key file seems to be corrupted" );
            res = TEE_ERROR_CORRUPT_OBJECT;
            goto find_key_exit;
        }

        it = attr_buf;

        key_len = *(uint32_t*) (void*) it;
        it += sizeof(uint32_t);
        id = *(uint32_t*) (void*) it;
        it += sizeof(uint32_t);
        iv_len = *(uint32_t*) (void*) it;
        it += sizeof(uint32_t);
        iv = TEE_Malloc( iv_len, 0 );
        memcpy( iv, it, iv_len );
        it += iv_len;
        
        key_attr_len = total_size - 4*sizeof(uint32_t) - iv_len;
        key_attr = TEE_Malloc( key_attr_len, 0 );
        memcpy( key_attr, it, key_attr_len );

        /* Check the header id vs. the key id */
        res = unpack_attrs( key_attr, key_attr_len, 
                           &attrs, &attr_count );
        CHECK_GOTO( res, find_key_exit, 
                    "Unpack_attrs() Error" );
        res = TEE_AllocateTransientObject( TEE_TYPE_AES, 
                                           key_len,
                                           &handle );
        CHECK_GOTO( res, find_key_exit, 
                    "TEE_AllocateTransientObject() Error" );
    
        res = TEE_PopulateTransientObject( handle, attrs, 
                                           attr_count );
        CHECK_GOTO( res, find_key_exit, 
                    "TEE_PopulateTransientObject() Error" );

        res = TEE_AllocateOperation( dec_op, TEE_ALG_AES_CTR,
                                     TEE_MODE_DECRYPT, 
                                     key_len );
        CHECK_GOTO( res, find_key_exit,
                    "TEE_AllocateOperation() Error" );
            
        res = TEE_SetOperationKey( *dec_op, handle );
        CHECK_GOTO( res, find_key_exit, 
                    "TEE_SetOperationKey() Error" );
    
        cnt_a = read_cntpct();
        TEE_CipherInit( *dec_op, iv, iv_len, 0 );

        res = TEE_CipherDoFinal( *dec_op, (void*) h->aes_id,
                                 sizeof(uint32_t), 
                                 (void*) &cap_id,
                                 &id_len );
        cnt_b = read_cntpct();
        timestamps[curr_ts].encryption += cnt_b - cnt_a;
        CHECK_GOTO( res, find_key_exit,
                    "TEE_CipherDoFinal() Error" );      
    
        if( id == cap_id ) {
            DMSG( "Found AES Key %08x", id );
            *gl_id = id;
            *gl_iv_len = iv_len;
            *gl_key_len = key_len;
            *gl_iv = TEE_Malloc( *gl_iv_len, 0 );
            memcpy( *gl_iv, iv, iv_len );
            goto find_key_setup_keys;       
        }
    
        TEE_Free( attr_buf );
        TEE_Free( attrs );
        TEE_Free( key_attr ); 
        TEE_Free( iv );
        iv = NULL;
        attrs = NULL;
        attr_buf = NULL;
        key_attr = NULL;
        TEE_FreeOperation( *dec_op );
        TEE_FreeTransientObject( handle );
    }

    if( key_not_found( *gl_iv, *gl_id, *gl_iv_len, *gl_key_len ) ) {
        res = TEE_ERROR_NOT_SUPPORTED;
        CHECK_SUCCESS( res, "Find_key() AES key not found" );
    }

    return res;

find_key_setup_keys:
    res = TEE_AllocateOperation( enc_op, TEE_ALG_AES_CTR,
                                 TEE_MODE_ENCRYPT, *gl_key_len );
    CHECK_GOTO( res, find_key_exit, 
                "TEE_AllocateOperation Error %02x", res );

    res = TEE_SetOperationKey( *enc_op, handle );
    CHECK_GOTO( res, find_key_exit, 
                   "TEE_SetOperationKey() Error" );

    res = TEE_AllocateOperation( sha_op, TEE_ALG_SHA256,
                                 TEE_MODE_DIGEST, 0 );
    CHECK_GOTO( res, find_key_exit, 
                    "TEE_AllocateOperation() Error" );

find_key_exit:
    TEE_FreeTransientObject( handle );
    if( iv != NULL )
        TEE_Free( iv );
    if( attrs != NULL )
        TEE_Free( attrs );
    if( attr_buf != NULL )
        TEE_Free( attr_buf );
    if( key_attr != NULL )
        TEE_Free( key_attr );
    return res;
}

/* Constructs the TrustedCap header*/
TEE_Result fill_header( struct TrustedCap* cap, 
                        TEE_OperationHandle op,
                        uint8_t *iv, uint32_t iv_len, uint32_t id,
                        unsigned char* hash, size_t hashlen, size_t
                        fsize ) {
    TEE_Result res = TEE_SUCCESS;
    uint32_t   id_len = 4;
    uint64_t   cnt_a, cnt_b;

    memset( cap, 0, sizeof( struct TrustedCap ) );
    memcpy( cap->pad, "TRUSTEDCAP\0", sizeof( cap->pad ) );
    
    /* Encrypt the capsule ID */
    cnt_a = read_cntpct();
    TEE_CipherInit( op, iv, iv_len, 0 );
    res = TEE_CipherDoFinal( op, ( char*) &id, sizeof(uint32_t), 
                             cap->aes_id, &id_len );
    cnt_b = read_cntpct();
    timestamps[curr_ts].encryption += cnt_b - cnt_a;
    CHECK_SUCCESS( res, "TEE_CipherDoFinal() Error" );

    DMSG( "ID: %02x%02x%02x%02x\n", cap->aes_id[0], cap->aes_id[1], 
                                cap->aes_id[2], cap->aes_id[3] );
    cap->capsize = fsize;
    memcpy( cap->hash, hash, hashlen );

    return res;
}

/* Read the TrustedCap header */
void read_header( unsigned char* file_contents, struct TrustedCap* cap ) {
    // Copy the header from the file contents into the struct
    memcpy( cap, file_contents, sizeof( struct TrustedCap ) );
}

/* Write the TrustedCap header */
// int write_header( struct TrustedCap* cap ) {
//     memcpy(&cap_head.header, cap, sizeof(struct TrustedCap));
//     return 0;
// }

void parse_kv_store( unsigned char* input, size_t inlen, 
                     struct capsule_text* cap ) {
    unsigned char*  pairs[MAX_NUM_KEYS]; // Make array of maximum key, value pairs
    struct kv_pair  kv_store[MAX_NUM_KEYS];
    int             last = 0,
                    start = 0,
                    end = 0,
                    total_num = 0;
    unsigned int    match_state = 0;
    size_t          pair_len;
    bool            matched = false;
    unsigned char*  delim = (unsigned char*) ";";
    int             delim_len = strlen((char*) delim);

    // First pass to parse into key value pairs
    do {
        // Must set matched to false or find_delimiter will just return 0
        matched = false;

        // Find the range at which the delimiter exists
        find_delimiter(input+last, inlen - last, &start, &end, &match_state, 
                       &matched, delim, delim_len);

        // MAX_NUM_KEYS is a hack to avoid having to do two passes for KV pairs
        // We could do away with MAX_NUM_KEYS and do one pass finding the number
        // of delimiters, alloc the array, then fill it with the pairs. 
        if (total_num < MAX_NUM_KEYS) {
            // Need to differentiate between all cases and the last case. 
            if (matched == true) {
                // Since find_delimiter starts at input+last, start holds the
                // size of the range (find_delimiter treats input+last as offset
                // 0).
                pairs[total_num] = TEE_Malloc(start * sizeof(unsigned char), 0);

                // Copy over the range (starting at input+last and ending at 
                // start) 
                TEE_MemMove(pairs[total_num], input + last, start);

                // Make sure it is null terminated, use start - 1 because we 
                // want to get rid of the ';'
                pairs[total_num][start - 1] = '\0';

                // Advance the offset to check
                last += end;

                // Increment the total number of keys
                total_num++;
            } else {
                // This is a special case because it will not have a start and
                // end value (because the match failed). So we assume it is the
                // last range.
                pairs[total_num] = TEE_Malloc((inlen - last) * sizeof(unsigned char), 0);
                TEE_MemMove(pairs[total_num], input+last, (inlen - last));

                // This removes the \n character
                pairs[total_num][(inlen - last - 1)] = '\0';

                // Increment the total number of keys
                total_num++;

                // Technically not necessary, as matched should equal false
                break;
            }
        }
    } while(matched == true);

    // Change the delimiter to the key, value pair delimiter
    // Might want to think about making this a global variable
    delim = (unsigned char*) ":";

    // Parse each pair
    for (int i = 0; i < total_num; i++) {
        // Get the length of the kv pair
        pair_len = strlen((char*) pairs[i]);

        // Initialize the find_delimiter variables
        last = 0, start = 0, end = 0;
        matched = false;

        find_delimiter( pairs[i], pair_len, &start, &end, &match_state, 
                       &matched, delim, delim_len);

        // Create memory for the key (size start)
        kv_store[i].key = TEE_Malloc(start * sizeof(unsigned char), 0);

        // Copy the key (starting at pairs[i] with size start)
        TEE_MemMove(kv_store[i].key, pairs[i], start);

        // Null terminate the key (removing the delimiter)
        kv_store[i].key[start - 1] = '\0';

        // Update the key length
        kv_store[i].key_len = strlen((char*) kv_store[i].key);

        // Advance the offset and clear the matched variable
        last += end;
        matched = false;

        find_delimiter( pairs[i]+last, pair_len - last, &start, &end, &match_state, 
                       &matched, delim, delim_len);

        // Create memory for the value, since it doesn't have a delimiter,
        // increase the size by one (for the null terminator)
        kv_store[i].value = TEE_Malloc((pair_len - last + 1) * sizeof(unsigned char), 0);

        // Copy the value over (starting at pairs[i] + last with size pair_len -
        // last)
        TEE_MemMove(kv_store[i].value, pairs[i] + last, (pair_len - last));
        
        // Null terminate the string
        kv_store[i].value[(pair_len - last)] = '\0';

        // Update the length for value
        kv_store[i].val_len = strlen((char*) kv_store[i].value);
    }

    // Malloc the space for the array of KV pairs
    cap->kv_store_buf = TEE_Malloc(sizeof(struct kv_pair) * total_num, 0); // Allocate memory
    
    // Copy the temp array into the global one
    TEE_MemMove(cap->kv_store_buf, kv_store, sizeof(struct kv_pair) * total_num);
    
    // Update the number of items
    cap->kv_store_len = total_num;
}

void serialize_kv_store( unsigned char* kv_string, size_t total_len ) {
    int last = 0;

    // Iterate through the list of key value pairs to create a string
    for (unsigned int i = 0; i < cap_head.kv_store_len; i++) {
        // Size the kv pair string (key_len, val_len, 1 for ':', 1 for ';', and
        // one for \0)
        int str_len = cap_head.kv_store_buf[i].key_len + 1 + 
                      cap_head.kv_store_buf[i].val_len + 1 + 1;

        // Temp string
        char temp[str_len];

        // Format the values into our temp string
        snprintf( temp, str_len, "%s:%s;", 
                 cap_head.kv_store_buf[i].key, cap_head.kv_store_buf[i].value);
        
        // Copy the temp string into our final string
        TEE_MemMove(kv_string + last, temp, str_len);
        
        // Increase the offset, but subtract one to overwrite the null terminator
        last += str_len - 1;
    }

    // Add null terminator at end
    kv_string[total_len] = '\0';
}

int get_kv_string_len( void ) {
    int kv_len = 0;
    // Figure out how large to make the key-value store buffer
    for (unsigned int i = 0; i < cap_head.kv_store_len; i++) {
        kv_len += cap_head.kv_store_buf[i].key_len + 1; // Key + :
        kv_len += cap_head.kv_store_buf[i].val_len + 1; // Val + ;
    }
    return kv_len;
}

/*
 * Finds the delimiter in a string.
 * The range given doesn't quite work for single character delimiters. See the
 * kv parsing for how to use this with single character delimiters.
 */ 
void find_delimiter( unsigned char* buf, size_t blen, int* dstart, 
                     int* dend, unsigned int* state, bool *matched, 
                     unsigned char* delim, size_t dlen ) {
    unsigned int n = 0;

    // I'm not sure why this is here...
    if( *matched == true ) {
        *dstart = 0;
        *dend = 0;
        return;
    }

    for( n = 0; n < blen; n++ ) {
        if( *state == dlen ) {
            *matched = true;
            *state = 0;
                
            *dend = n;
            *dstart = n - dlen + 1; 

            break;
        }

        if( buf[n] == delim[*state] ) {
            ( *state )++;
        } else {
            if( buf[n] == delim[0] ) {
                *state = 1;
                *dstart = n;
            } else {
                *state = 0;
                *dstart = 0 ;
            }
        } 
    }
}

/* Separate the data and policy sections of the trusted capsule */
void sep_parts( unsigned char* input, size_t inlen, 
                struct capsule_text* cap ) {

    // Only four parts b/c we get input w/o header (policy, kv store, log, data)
    unsigned char  *parts[4];
    int             last = 0,   // Offset tracker
                    index = 0,  // Index of parts array
                    start = 0,  // Start offset of delimiter (relative to input + last)
                    end = 0;    // End offset of delimiter (relative to input + last)
    unsigned int    match_state = 0;
    bool            matched;
    unsigned char   delimiter[DELIMITER_SIZE] = DELIMITER;

    // Loop to parse the parts
    do {
        matched = false;
        find_delimiter(input+last, inlen - last, &start, &end, &match_state, 
                       &matched, delimiter, DELIMITER_SIZE);

        // We have a fixed number of capsule parts. 
        // TODO: make 4 a global variable
        if (index < 4) {
            if (matched == true) {
                // Create space for this part
                parts[index] = TEE_Malloc(start * sizeof(unsigned char)+1, 0);

                // Copy the data over
                TEE_MemMove(parts[index], input + last, start);

                // Null terminate it
                parts[index][start] = '\0';

                // Move offset pointer forward
                last += end;

                // Increase the part array index
                index++;
            } else {
                // If we did not match, but still have parts left, this must be
                // the last part.
                parts[index] = TEE_Malloc((inlen - last) * sizeof(unsigned char)+1, 0);
                TEE_MemMove(parts[index], input+last, (inlen - last));
                parts[index][(inlen - last) * sizeof(unsigned char)] = '\0';
                index++;
                break;
            }
        }
    } while(matched == true);

    // Note you MUST + 1 to the sizes because of the added null character
    // Set the policy length
    cap->policy_len = strlen((char *) parts[0]);
    // Create space, NOTE: you must +1 to include null terminator set in the loop
    cap->policy_buf = TEE_Malloc(cap->policy_len * sizeof(unsigned char) + 1, 0);
    // Copy over the policy
    TEE_MemMove(cap->policy_buf, parts[0], cap->policy_len);

    // Pass the kv part to the parser
    parse_kv_store(parts[1], strlen((char *) parts[1]), cap);

    cap->log_len = strlen((char *) parts[2]);
    cap->log_buf = TEE_Malloc(cap->log_len * sizeof(unsigned char) + 1, 0);
    TEE_MemMove(cap->log_buf, parts[2], cap->log_len);
    
    cap->data_len = strlen((char *) parts[3]);
    cap->data_buf = TEE_Malloc(cap->data_len * sizeof(unsigned char) + 1, 0);
    TEE_MemMove(cap->data_buf, parts[3], cap->data_len);

    // Copy data into the shadow buffer, this is used if the close policy fails
    // so the close function can just write back the same capsule
    cap->data_shadow_buf = TEE_Malloc(cap->data_len * sizeof(unsigned char), 0);
    TEE_MemMove(cap->data_shadow_buf, cap->data_buf, cap->data_len);
    cap->data_shadow_len = cap->data_len;

    // Free the parts
    for (int i = 0; i < 4; i++) {
        TEE_Free(parts[i]);
    }
}

/* De-serialize the AES key */
TEE_Result unpack_attrs( const uint8_t* buf, uint32_t blen,
                         TEE_Attribute **attrs, 
                         uint32_t *attrs_count ) {
    TEE_Result res = TEE_SUCCESS;
    TEE_Attribute* a = NULL;
    uint32_t num_attrs = 0;
    const size_t num_attrs_size = sizeof( uint32_t );
    const struct attr_packed *ap;

    if( blen == 0 ) 
        goto out;

    if( ( (uintptr_t) buf & 0x3 ) != 0 || blen < num_attrs_size )
        return TEE_ERROR_BAD_PARAMETERS;
    
    num_attrs = *(uint32_t*) (void *) buf;
    if( ( blen - num_attrs_size ) < ( num_attrs * sizeof(*ap) ) ) 
        return TEE_ERROR_BAD_PARAMETERS;

    ap = (const struct attr_packed*) \
         (const void*) (buf+num_attrs_size);

    if( num_attrs > 0 ) {
        size_t n;

        a = TEE_Malloc( num_attrs * sizeof( TEE_Attribute ), 0 );
        if( !a )
            return TEE_ERROR_OUT_OF_MEMORY;
        for( n = 0; n < num_attrs; n++ ) {
            a[n].attributeID = ap[n].id;
            if( ap[n].id & TEE_ATTR_BIT_VALUE ) {
                a[n].content.value.a = ap[n].a;
                a[n].content.value.b = ap[n].b;
                continue;
            }

            a[n].content.ref.length = ap[n].b;

            if( ap[n].a ) {
                if( ap[n].a + ap[n].b > blen ) {
                    res = TEE_ERROR_BAD_PARAMETERS;
                    goto out;
                }
            }

            a[n].content.ref.buffer = (void*) ( (uintptr_t) buf + 
                                      (uintptr_t) ap[n].a );
        }
    }

out:
    if( res == TEE_SUCCESS ) {
        *attrs = a;
        *attrs_count = num_attrs;
    } else {
        TEE_Free( a );
    }
    return res;
}
