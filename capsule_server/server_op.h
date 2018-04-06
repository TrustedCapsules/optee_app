#ifndef SERVER_ENC_H
#define SERVER_ENC_H

#define NUM_CAPSULES sizeof( capsule_data_array ) / sizeof( struct capsule_data )

/* Stores info about the capsule */
struct capsule_entry {
	unsigned char *key;
	uint32_t	   key_len;
	uint32_t 	   id;
	uint8_t 	  *iv;
	uint32_t	   iv_len;
	// uint32_t 	   chunk_size;
	uint32_t       version;
	int (*reply)( int, int, AMessage*, char* );
};

/* Stores info about states */
struct capsule_state {
	uint32_t    id;
	char        key[STATE_SIZE];
	char        val[STATE_SIZE];
};

extern struct capsule_entry capsule_entry_map[NUM_CAPSULES];
extern struct capsule_state state_map[NUM_CAPSULES*MAX_STATES_PER_CAPSULE];

uint32_t change_endianness( unsigned char *id );

void register_capsule_entry(void);
void register_state(void);

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
