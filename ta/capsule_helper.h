#ifndef CAPSULE_HELPER_H
#define CAPSULE_HELPER_H

struct attr_packed {
    uint32_t id;
    uint32_t a;
    uint32_t b;
};

/*
 * For timing
 */
unsigned long long read_cntpct(void);

/*
 * Process a block of data (encrypt/decrypt)
 */
TEE_Result process_aes_block( unsigned char* ctx, size_t clen,
                              unsigned char* ptx, size_t* plen,
                              uint8_t* iv, uint32_t iv_len, uint32_t ctr,
                              bool first, bool last, TEE_OperationHandle op );

/*
 * Hash operations
 */
TEE_Result hash_data( unsigned char* payload, size_t payload_len,
                      unsigned char* hash, size_t hlen );
TEE_Result hash_block( unsigned char* ptx, size_t plen, unsigned char* hash, 
                       size_t hlen, bool last, TEE_OperationHandle op );
bool compare_hashes( unsigned char* hash1, unsigned char* hash2, size_t hlen );

/*
 * Capsule text init/cleanup
 */
void initialize_capsule_text( struct capsule_text* cap );
void finalize_capsule_text( struct capsule_text* cap );

/*
 * Key operations
 */
bool key_not_found( uint8_t* gl_iv, uint32_t gl_id, uint32_t gl_iv_len, 
                    uint32_t gl_key_len );
TEE_Result find_key( struct TrustedCap* h, TEE_ObjectHandle file,
                     TEE_OperationHandle* dec_op, TEE_OperationHandle* enc_op,
                     TEE_OperationHandle* sha_op,  uint32_t* gl_id, 
                     uint32_t* gl_iv_len, uint32_t* gl_key_len, 
                     uint8_t** gl_iv );

/*
 * Header operations
 */
TEE_Result fill_header( struct TrustedCap* cap, TEE_OperationHandle op,
                        uint8_t* iv, uint32_t iv_len, uint32_t id, 
                        unsigned char* hash, size_t hashlen, size_t fsize );
void read_header( unsigned char* file_contents, struct TrustedCap* cap );

/*
 * Parsing operations
 */
void serialize_kv_store( unsigned char* kv_string, int len);
void parse_kv_store( unsigned char* input, size_t length, 
                     struct capsule_text* cap );
int get_kv_string_len( void );

void find_delimiter( unsigned char* buf, size_t blen, int* dstart, 
                     int* dend, unsigned int* state, bool *matched, 
                     unsigned char* delim, size_t dlen );
void sep_parts( unsigned char* input, size_t inlen, 
                struct capsule_text* cap );

TEE_Result unpack_attrs( const uint8_t* buf, uint32_t blen,
                         TEE_Attribute** attrs, uint32_t* attrs_count);

#endif /* CAPSULE_HELPER_H */

