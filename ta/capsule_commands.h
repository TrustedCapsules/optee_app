#ifndef CAPSULE_COMMANDS_H
#define CAPSULE_COMMANDS_H

/*
 * Register keys for testing
 */
TEE_Result register_aes_key( uint32_t param_type, 
							 TEE_Param params[4] );

/*
 * Secure storage state operations (for testing)
 */
TEE_Result get_state( uint32_t param_type, TEE_Param params[4] );
TEE_Result set_state( uint32_t param_type, TEE_Param params[4] );
TEE_Result get_buffer( uint32_t param_type, TEE_Param params[4] );

/*
 * Actual capsule operations
 */
TEE_Result capsule_close( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_open( uint32_t param_type, TEE_Param params[4] );

/*
 * Capsule network operations
 */
TEE_Result capsule_open_connection( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_close_connection( uint32_t param_type, 
									 TEE_Param params[4] );
TEE_Result capsule_recv_connection( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_send_connection( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_send( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_recv_header( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_recv_payload( uint32_t param_type, TEE_Param params[4] );

#endif /* CAPSULE_COMMANDS_H */
