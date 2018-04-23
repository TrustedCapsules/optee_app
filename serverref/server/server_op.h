#ifndef SERVER_ENC_H
#define SERVER_ENC_H

#define NUM_CAPSULES sizeof( capsule_data_array ) / sizeof( struct capsule_data )


extern struct capsule_entry capsule_entry_map[NUM_CAPSULES];
extern struct capsule_state state_map[NUM_CAPSULES*MAX_STATES_PER_CAPSULE];

uint32_t change_endianness( unsigned char *id );

struct capsule_entry* get_curr_capsule( uint32_t capsule_id );

int encrypt_data( void *ptx, void *ctx, size_t len, 
				  struct capsule_entry *entry );

int decrypt_data( void *ctx, void *ptx, size_t len,
				  struct capsule_entry *entry );

int send_data( int fd, void *buf, size_t buf_len );
int recv_data( int fd, void *buf, size_t buf_len );
int hash_data( const unsigned char* buffer, size_t buflen,
			   unsigned char* hash, size_t hashlen );

#endif /* SERVER_ENC_H */
