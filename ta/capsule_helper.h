#ifndef CAPSULE_HELPER_H
#define CAPSULE_HELPER_H

struct attr_packed {
	uint32_t id;
	uint32_t a;
	uint32_t b;
};

unsigned long long read_cntpct(void);

int getfield( lua_State *L, int key, int tindex ); 
TEE_Result lua_read_redact( lua_State *L, int state_tgid, int state_fd,
							unsigned char *bp, uint32_t len );
TEE_Result lua_get_replacement_char( lua_State *L, char* replace );
TEE_Result lua_get_server_ip_port( lua_State *L, char* ts, int* port );
TEE_Result lua_load_policy( lua_State *L, const char* buf );
void lua_start_context( lua_State **L );
void lua_close_context( lua_State **L );

TEE_Result unpack_attrs( const uint8_t*, uint32_t,
						 TEE_Attribute**, uint32_t*);

void sep_policy_and_data( unsigned char*, size_t, 
						  struct capsule_text*, uint8_t*, 
						  bool *matched, unsigned char* );

void initialize_capsule_text( struct capsule_text* );
void initialize_capsule_entries( struct cap_text_entry *p,
				                 int state_tgid, int state_fd,
								 unsigned int d_pos );

struct cap_text_entry* find_capsule_entry( struct CapTextList *head,
										   int state_tgid, int state_fd );

uint32_t read_block( int fd, void* buf, size_t blen, uint32_t offset );
uint32_t write_block( int fd, void* buf, size_t blen, uint32_t offset );

uint32_t calc_chk_len( uint32_t, uint32_t );
uint32_t calc_chk_num( uint32_t, uint32_t );

bool verify_hash( uint32_t, struct HashList*, unsigned char*, size_t);	
int read_hash( int, unsigned char*, size_t, uint32_t, uint32_t );
int write_hash( int, unsigned char*, size_t, struct HashList*,
				 uint32_t, uint32_t );
bool compare_hashes( unsigned char*, unsigned char*, size_t );
TEE_Result hash_hashlist( struct HashList*, unsigned char*, 
					      size_t, TEE_OperationHandle );
bool is_in_hashlist( struct HashList*, uint32_t );
void add_to_hashlist( unsigned char*, size_t, struct HashList*, uint32_t );
void free_hashlist( struct HashList* );

TEE_Result hash_data( unsigned char* payload, size_t payload_len,
					  unsigned char* hash, size_t hlen );
TEE_Result hash_block( unsigned char*, size_t, unsigned char*, size_t,
					   bool, TEE_OperationHandle );

TEE_Result process_aes_block( unsigned char*, size_t*, 
						  	  unsigned char*, size_t,
						  	  uint8_t*, uint32_t, uint32_t,
						  	  bool, bool, TEE_OperationHandle );
TEE_Result read_enc_file_block( int, unsigned char*, size_t, size_t*,
								uint32_t, uint32_t, uint32_t, 
								uint32_t, uint32_t, unsigned char*, 
								uint32_t, TEE_OperationHandle );
TEE_Result write_enc_file_block( int, unsigned char*, size_t, size_t*,
								 uint32_t, uint32_t, uint32_t, 
								 uint32_t, unsigned char*, uint32_t,
								 TEE_OperationHandle );

TEE_Result truncate_data( int, struct HashList*, uint32_t, uint32_t,
						  struct capsule_text* );

bool key_not_found( uint8_t*, uint32_t, uint32_t, uint32_t );
TEE_Result find_key( struct TrustedCap*, TEE_ObjectHandle,
					 TEE_OperationHandle*, TEE_OperationHandle*,
					 TEE_OperationHandle*,  uint32_t*, uint32_t*,
					 uint32_t*, uint32_t*, uint8_t** );

TEE_Result fill_header( struct TrustedCap*, TEE_OperationHandle,
						uint8_t*, uint32_t, uint32_t, 
			   			unsigned char*, size_t, size_t );
int read_header( int, struct TrustedCap* );
int write_header( int, struct TrustedCap* );

void free_caplist( struct CapTextList *head );



#endif /* CAPSULE_HELPER_H */

