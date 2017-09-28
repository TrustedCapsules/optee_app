#ifndef CAPSULE_COMMANDS_H
#define CAPSULE_COMMANDS_H

TEE_Result capsule_write_evaluate( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_write( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_ftruncate( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_fstat( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_pread( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_read( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_lseek( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_close( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_create( uint32_t param_type, 
				    	   TEE_Param params[4] );
TEE_Result capsule_change_policy( uint32_t param_type, 
				    	   		  TEE_Param params[4] );
TEE_Result capsule_open( uint32_t param_type, TEE_Param params[4] );
TEE_Result register_rsa_key( uint32_t param_type, 
							 TEE_Param params[4] );
TEE_Result register_aes_key( uint32_t param_type, 
							 TEE_Param params[4] );
TEE_Result get_state( uint32_t param_type, TEE_Param params[4] );
TEE_Result set_state( uint32_t param_type, TEE_Param params[4] );

TEE_Result capsule_open_connection( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_close_connection( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_recv_connection( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_send_connection( uint32_t param_type, TEE_Param params[4] );

TEE_Result capsule_send( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_recv_header( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_recv_payload( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_clear_benchmark( uint32_t param_type, TEE_Param params[4] );
TEE_Result capsule_collect_benchmark( uint32_t param_type, TEE_Param params[4] );

#endif /* CAPSULE_COMMANDS_H */
