#ifndef CAPSULE_OP_H
#define CAPSULE_OP_H

/* Current implementation leaves some security holes that 
 * should be fixed later. Although this shouldn't impact 
 * the direction of the research. 
 *
 * 1) The hashlist should also be encrypted
 */


TEE_Result do_write_new_policy_network( int, unsigned char*, uint32_t );
TEE_Result do_write_new_policy( int, int, uint32_t );
TEE_Result do_move_data_up( int, uint32_t );
TEE_Result do_move_data_down( int, uint32_t );
int do_lseek( int, int, int, FILE_POS, bool );
TEE_Result do_read( int, int, int, unsigned char*, uint32_t*, bool, bool );
TEE_Result do_write( int, int, int, unsigned char*, uint32_t*, bool, bool );
TEE_Result do_open( int, int, int );
void do_close( int, int );
TEE_Result do_create( int, int );
TEE_Result do_change_policy( int, int, size_t );
TEE_Result do_change_policy_network( int, unsigned char*, size_t );
TEE_Result do_register_aes( uint32_t, uint32_t, uint32_t, uint32_t,
							uint8_t*, uint32_t, uint8_t*, uint32_t );
TEE_Result do_register_rsa( uint32_t, uint32_t, uint8_t*, uint32_t );
TEE_Result do_open_connection( char*, int, int* );
TEE_Result do_send_connection( int, void*, int* );
TEE_Result do_recv_connection( int, void*, int* );
TEE_Result do_close_connection( int );

TEE_Result do_fstat( uint32_t* data_length );
TEE_Result do_ftruncate( int fd, uint32_t new_data_length );

TEE_Result do_set_state( unsigned char* key, uint32_t klen,
						 unsigned char* val, uint32_t vlen );

TEE_Result do_get_state( unsigned char* key, unsigned char* val, uint32_t vlen );

TEE_Result do_send( int fd, void *buf, int *len, int op_code, int rv );
	
TEE_Result do_recv_payload( int fd, void* hash, int hlen,
			   				void* buf, int len );
TEE_Result do_recv_header(int fd, AMessage **msg );
TEE_Result do_run_policy( int fd, lua_State *L, const char* policy, SYSCALL_OP n );
TEE_Result do_load_policy( int fd );

#endif /* CAPSULE_OP_H */
