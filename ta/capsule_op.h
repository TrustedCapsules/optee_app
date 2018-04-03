#ifndef CAPSULE_OP_H
#define CAPSULE_OP_H

/*
 * For testing, registers the capsule keys
 */
TEE_Result do_register_aes( uint32_t keyType, uint32_t id, uint32_t chSize, 
							uint32_t keyLen, uint8_t* attr, uint32_t attrlen, 
							uint8_t* iv, uint32_t ivlen );

/*
 * Capsule operations
 */
TEE_Result do_open( unsigned char* contents, int size );
TEE_Result do_close( TEE_Result res, unsigned char* encrypted_file,
					 size_t* new_len, bool flush_flag );

/*
 * Policy operations
 */
TEE_Result do_run_policy( lua_State *L, const char* policy, SYSCALL_OP n );
TEE_Result do_load_policy(void);

/*
 * Network policy functions (get new policy)
 */
TEE_Result do_write_new_policy_network( unsigned char* policy, 
										uint32_t len );
TEE_Result do_change_policy_network( unsigned char* policy, 
									 size_t newlen );

/*
 * Network operations
 */
TEE_Result do_open_connection( char* ip_addr, int port, int* fd );
TEE_Result do_close_connection( int fd );
TEE_Result do_recv_connection( int fd, void* buf, int* len );
TEE_Result do_send_connection( int fd, void* buf, int* len );
TEE_Result do_send( int fd, void *buf, int *len, int op_code, int rv );
TEE_Result do_recv_payload( int fd, void* hash, int hlen,
			   				void* buf, int len );
TEE_Result do_recv_header(int fd, AMessage **msg );

/*
 * Secure storage state operations
 */
TEE_Result do_set_state( unsigned char* key, uint32_t klen,
						 unsigned char* val, uint32_t vlen );
TEE_Result do_get_state( unsigned char* key, unsigned char* val, 
						 uint32_t vlen );

#endif /* CAPSULE_OP_H */
