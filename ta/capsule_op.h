#ifndef CAPSULE_OP_H
#define CAPSULE_OP_H

#include <capsulePolicy.h>
#include <capsuleServerProtocol.h>

/*
 * For testing, registers the capsule keys
 */
TEE_Result do_register_aes( uint32_t keyType, uint32_t id, 
							uint32_t keyLen, uint8_t* attr, uint32_t attrlen, 
							uint8_t* iv, uint32_t ivlen );

/*
 * Capsule operations
 */
TEE_Result do_open( unsigned char* contents, int size );
unsigned char* do_close( TEE_Result res, size_t* cap_to_write_len,
						 bool flush_flag );

/*
 * Policy operations
 */
TEE_Result do_run_policy( lua_State *L, const char* policy, SYSCALL_OP n );

TEE_Result do_load_policy(void);

TEE_Result do_redact(char *buf, char **newBuf, char *replaceString, 
							size_t start, size_t end, size_t len);

TEE_Result get_time_from_remote(char *ip_addr, uint16_t port, TEE_Time *t);

/*
 * Network policy functions (get new policy)
 */
TEE_Result do_write_new_policy_network(unsigned char *policy,
										   uint32_t len);
TEE_Result do_change_policy_network( unsigned char* policy, 
									 size_t newlen );

/*
 * Network operations
 */
TEE_Result do_open_connection( char* ip_addr, int port, int* fd );
TEE_Result do_close_connection( int fd );
TEE_Result do_recv_connection( int fd, void* buf, int* len );
TEE_Result do_send_connection( int fd, void* buf, int* len );
TEE_Result do_send( int fd, void *buf, size_t len, int op_code, int rv );
TEE_Result do_recv_payload( int fd, void* hash, int hlen,
			   				void* buf, int len );
TEE_Result do_recv_header(int fd, msgReplyHeader *msg );

/*
* TrustedApp KV metadata operations.
*/

RESULT do_get_capsule_state(unsigned char *key, unsigned char *val, uint32_t vlen);
RESULT do_set_capsule_state(unsigned char *key, unsigned char *val, uint32_t klen, uint32_t vlen);
TEE_Result do_append_blacklist (const char* key, size_t size, const WHERE w);
TEE_Result do_remove_from_blacklist(const char *str, size_t strLen, const WHERE w);

/*
* Remote KV operations.
*/

RESULT do_get_remote_state(unsigned char *key, unsigned char *value,
							   uint32_t keyLen, uint32_t valueLen, char *ip_addr, uint16_t port);
RESULT do_set_remote_state(unsigned char *key, unsigned char *value, 
							uint32_t keyLen, uint32_t valueLen,
						   char *ip_addr, uint16_t port);
/*
 * Secure storage state operations
 */
TEE_Result
do_set_state(unsigned char *key, uint32_t klen,
			 unsigned char *val, uint32_t vlen);
RESULT do_get_state( unsigned char* key, unsigned char* val, 
						 uint32_t vlen );
char* do_get_buffer( BUF_TYPE t, size_t *len, TEE_Result *res );

#endif /* CAPSULE_OP_H */
