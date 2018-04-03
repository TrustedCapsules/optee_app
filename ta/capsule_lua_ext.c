#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_internal_api_extensions.h>
#include <amessage.pb-c.h>
#include <serialize_common.h>
#include <capsule.h>
#include <lua.h>
#include <luaconf.h>
#include <lauxlib.h>
#include "capsule_structures.h"
#include "capsule_ta.h"
#include "capsule_helper.h"
#include "capsule_op.h"
#include "capsule_lua_ext.h"

// static int getdataoffset(void) {

// 	struct cap_text_entry *p;
// 	int 				   data_pos = -1;

// 	LIST_FOREACH( p, &cap_head.proc_entries, entries ) {
// 		if( p->state_tgid == curr_tgid &&
// 			p->state_fd == curr_fd ) {
// 			data_pos = p->data_pos - cap_head.data_begin;
// 		}
// 	}

// 	return data_pos;
// }

static void delete_file(void) {
	/* The solution below is inelegant, but it gets the
	 * job done, even against TOCTTOU attacks.
	 *
	 * 1) Delete the statefile for this capsule
	 * 2) Zero the entire capsule from header down
	 * 3) Call unlink on the file
	 * 4) TEE_Panic out of the trusted capsule session
	 */
	int    fd;
	size_t file_length, nw, curr_length = 0;
	char   zero_block[BLOCK_LEN];
    uint32_t offset = 0;
    TEE_Result res;


	TEE_CloseAndDeletePersistentObject( stateFile );
	res = TEE_SimpleOpen( capsule_name, &fd );
	if( fd < 0 || res != TEE_SUCCESS ) {
		/* File no longer exists */
		goto delete_file_exit;
	}

    // TODO: add error checks
	res = TEE_SimpleLseek( fd, 0, TEE_DATA_SEEK_END, &file_length );

	memset( zero_block, 0, BLOCK_LEN );
	while( curr_length < file_length ) {
		res = TEE_SimpleWrite( fd, zero_block, BLOCK_LEN, &nw, offset );
        offset += nw;
		curr_length += nw;
	}	

	TEE_SimpleClose( fd );
	TEE_SimpleUnlink( capsule_name );

delete_file_exit:
	//MSG( "Deleting File %s...", capsule_name );
	TEE_Panic(0);
}

static int luaE_getgps( lua_State *L ) {
	
	TEE_GPS gps;

	/* Need to implement another system
	 * call to go grab a fake file that 
	 * contain the GPS (x,y) coordinate
	 */
	
	TEE_GetGPS( &gps );

	// MSG( "gps.longitude: %u, gps.latitude: %u", gps.longitude, gps.latitude );

	lua_pushinteger( L, gps.longitude );
	lua_pushinteger( L, gps.latitude );
	return 2;
}


static int luaE_getcurrtime( lua_State *L ) {
	TEE_Time t;
	TEE_GetREETime( &t );

	/* We don't really care about millis. 
	 * Second granularity should be okay for 
	 * policy applications */

	// MSG( "time: %u", t.seconds );

	lua_pushinteger( L, t.seconds );
    return 1;	
}

static int luaE_getserverstate( lua_State *L ) {
	
	TEE_Result 	  res;
	int           fd, rv, ts_port, len;
	char          ts_ip[IPV4_SIZE] = { 0 };
	unsigned char val[STATE_SIZE] = "none";
	const char*   key = luaL_checkstring(L, -1);
	AMessage     *msg;

	/* Uses the network functions in capsule_op
	 * to send a request in the following format:
	 *      send -> KEY (128B)
	 *      recv <- VAL or SPECIAL string for DEL file
	 * like state, this passes values by string.
	 * the Lua has facilities to convert it back 
	 * into floats or ints if it wants to
	 */

	/* FIXME: key only correct half the time for some reason */	
	//MSG( "key: %s, val: %s", key, val );
	
	/* Get the server ip:port from policy */
	res = lua_get_server_ip_port( L, ts_ip, &ts_port ); 
	if( res != TEE_SUCCESS ) luaL_error( L, "Lua_get_server_ip_port error" );

	/* Open connection to server */
	res = do_open_connection( ts_ip, ts_port, &fd );
	if( res != TEE_SUCCESS ) luaL_error( L, "Do_open_connection error" );

	/* Send the key */
	TEE_GenerateRandom( &rv, sizeof(int) );
	len = (int) strlen( key );
	res = do_send( fd, (void*) key, &len, REQ_STATE, rv );
	if( res != TEE_SUCCESS ) {
		do_close_connection( fd );
		luaL_error( L, "Do_send() error" );
	}
	
	/* Recv the val */
	res = do_recv_header( fd, &msg );
	if( res != TEE_SUCCESS ) {
		do_close_connection( fd );
		luaL_error( L, "Do_recv_header() error" );
	}
	
	if( msg->rvalue != rv ) {
		do_close_connection( fd );
		free_hdr( msg );
		luaL_error( L, "Magic value %d does not match from header (%d)",
						rv, msg->rvalue );
	}

	if( msg->op_code != RESP_STATE && msg->op_code != RESP_DELETE ) {
		do_close_connection( fd );
		free_hdr( msg );
		luaL_error( L, "Msg->op_code %d invalid (not RESP_STATE or RESP_DELETE)",
				 		msg->op_code );
	}

	if( msg->op_code == RESP_DELETE ) {
		do_close_connection( fd );
		free_hdr( msg );
		delete_file();
	}

	if( msg->payload_len > STATE_SIZE ) {
		do_close_connection( fd );
		free_hdr( msg );
		luaL_error( L, "Payload length %d is longer than max size %d", 
						msg->payload_len, STATE_SIZE );
	}


	if( msg->payload_len > 0 ) {
		res = do_recv_payload( fd, msg->hash.data, msg->hash.len,
						       val, msg->payload_len );
		if( res != TEE_SUCCESS ) {
			do_close_connection( fd );
			free_hdr( msg );
			luaL_error( L, "Do_recv_payload() error" );
		}
	}

	//MSG( "key: %s, val: %s", key, val );

	/* Push the retrieved value back on the stack */	
	lua_pushlstring( L, (const char*) val, strlen( (char*) val) );	
	do_close_connection( fd );
	free_hdr( msg );

	return 1;
}

static int luaE_reportlocid( lua_State *L ) {
	TEE_Result 	  res;
	TEE_GPS       gps;
	TEE_Time 	  t;
	int           fd, rv, ts_port, len;
	char          ts_ip[IPV4_SIZE] = { 0 };
	unsigned int  val[7];
	unsigned int  op = luaL_checkinteger( L, -1 );
	AMessage     *msg;

	/* Uses the network functions to report the
	 * GPS location and ID of the person accessing
	 * the trusted capsule:
	 * 		send -> LOCATION (128B) ID (128B)
	 * 		recv <- ACK or SPECIAL string for DEL file
	 */
		
	/* Get the server ip:port from policy */
	res = lua_get_server_ip_port( L, ts_ip, &ts_port ); 
	if( res != TEE_SUCCESS ) luaL_error( L, "Lua_get_server_ip_port error" );

	// MSG( "IP: %s, PORT: %d", ts_ip, ts_port );

	/* Open connection to server */
	res = do_open_connection( ts_ip, ts_port, &fd );
	if( res != TEE_SUCCESS ) luaL_error( L, "Do_open_connection error" );

	/* Send the key */
	TEE_GenerateRandom( &rv, sizeof(int) );
	TEE_GetGPS( &gps );
	TEE_GetREETime( &t );
	val[0] = gps.longitude;
	val[1] = gps.latitude;
	val[2] = curr_cred;
	val[3] = t.seconds;
	val[4] = op;
	val[5] = curr_len;
	// val[6] = getdataoffset(); 
	len = sizeof(val);

	res = do_send( fd, (void*) val, &len, REQ_SEND_INFO, rv );
	if( res != TEE_SUCCESS ) {
		do_close_connection( fd );
		luaL_error( L, "Do_send() error" );
	}

	// MSG( "Waiting for response..." );

	/* Recv the val */
	res = do_recv_header( fd, &msg );
	if( res != TEE_SUCCESS ) {
		do_close_connection( fd );
		luaL_error( L, "Do_recv_header() error" );
	}
	
	if( msg->rvalue != rv ) {
		do_close_connection( fd );
		free_hdr( msg );
		luaL_error( L, "Magic value %d does not match from header (%d)",
						rv, msg->rvalue );
	}

	if( msg->op_code != RESP_SEND_ACK && msg->op_code != RESP_DELETE ) {
		do_close_connection( fd );
		free_hdr( msg );
		luaL_error( L, "Msg->op_code %d invalid (not RESP_SEND_ACK or RESP_DELETE)",
				 		msg->op_code );
	}

	if( msg->op_code == RESP_DELETE ) {
		do_close_connection( fd );
		free_hdr( msg );
		delete_file();
		/* Will not return */
	}

	do_close_connection( fd );
	free_hdr( msg );

	return 0;
}

static int luaE_checkpolicychange( lua_State *L ) {
	TEE_Result 	  res;
	int           fd, rv, ts_port, len;
	char          ts_ip[IPV4_SIZE] = { 0 };
	unsigned int  version = luaL_checkinteger( L, -1 );
	unsigned char policy[POLICY_SIZE];
	AMessage     *msg;
	bool          policy_change = false;
    
	/* Uses the network functions to ask if policy has
	 * changed. 
	 * 		send -> policy version (32B) from policy file
	 * 		recv <- payload is 0 if no change, len of new policy if policy
	 * 				changed
	 * 		recv <- policy (size B)
	 *
	 * 1) Re-write the policy in the trusted capsule
	 * 2) Return 0 -> No change
	 *           1 -> Policy changed 
	 * 3) Whether the new policy takes immediate effect for this
	 *    round of policy evaluation depends on the policy 
	 */	  

	/* Get the server ip:port from policy */
	res = lua_get_server_ip_port( L, ts_ip, &ts_port ); 
	if( res != TEE_SUCCESS ) luaL_error( L, "Lua_get_server_ip_port error" );

	/* Open connection to server */
	res = do_open_connection( ts_ip, ts_port, &fd );
	if( res != TEE_SUCCESS ) luaL_error( L, "Do_open_connection error" );

	/* Send the policy change request */
	TEE_GenerateRandom( &rv, sizeof(int) );
	len = sizeof( version );
	res = do_send( fd, (void*) &version, &len, REQ_POLICY_CHANGE, rv );
	if( res != TEE_SUCCESS ) {
		do_close_connection( fd );
		luaL_error( L, "Do_send() error" );
	}
	
	/* Recv the val */
	res = do_recv_header( fd, &msg );
	if( res != TEE_SUCCESS ) {
		do_close_connection( fd );
		luaL_error( L, "Do_recv_header() error" );
	}
	
	if( msg->rvalue != rv ) {
		do_close_connection( fd );
		free_hdr( msg );
		luaL_error( L, "Magic value %d does not match from header (%d)",
						rv, msg->rvalue );
	}

	if( msg->op_code != RESP_POLICY_CHANGE && msg->op_code != RESP_DELETE ) {
		do_close_connection( fd );
		free_hdr( msg );
		luaL_error( L, "Msg->op_code %d invalid (not RESP_POLICY_CHANGE or"
					   " RESP_DELETE)", msg->op_code );
	}

	if( msg->op_code == RESP_DELETE ) {
		do_close_connection( fd );
		free_hdr( msg );
		delete_file();
	}

	if( msg->payload_len > POLICY_SIZE ) {
		do_close_connection( fd );
		free_hdr( msg );
		luaL_error( L, "Payload length %d is longer than max size %d", 
						msg->payload_len, POLICY_SIZE );
	}
	/* Grab the new policy */
	if( msg->payload_len > 0 ) {
		res = do_recv_payload( fd, msg->hash.data, msg->hash.len,
						       policy, msg->payload_len );
	
		// res = TEE_SimpleOpen( capsule_name, &fd_cap );
		// if( fd_cap < 0 || res != TEE_SUCCESS ) {
		// 	do_close_connection( fd );
		// 	free_hdr( msg );
		// 	luaL_error( L, "Unable to open file %s for policy update", 
		// 				   capsule_name );
		// }

		do_change_policy_network( policy, msg->payload_len ); 	
		// TEE_SimpleClose( fd_cap );
		policy_change = true;
	}

	/* Push policy_change onto the stack */
	lua_pushboolean( L, policy_change );
	do_close_connection( fd );
	free_hdr( msg );

	return 1;
}

static int luaE_deletefile( lua_State *L ) {
	UNUSED( L );	
	delete_file();
	/* It will never reach here */
	return 0;
}

// static int luaE_getdeclassifydest( lua_State *L ) {
// 	lua_pushlstring( L, curr_declassify_dest, 
// 					 strlen(curr_declassify_dest) );
// 	return 1;
// }

// static int luaE_getOffsetLen( lua_State *L ) {
	
// 	int data_pos = getdataoffset(); 

// 	if( data_pos == -1 ) {
// 		luaL_error( L, "curr_tgid: %d, curr_fd: %d cannot be found,"
// 					   " this should not be possible", 
// 					   curr_tgid, curr_fd ); 
// 	}

// 	if( data_pos > (int) cap_head.data_end - (int) cap_head.data_begin ) 
// 		curr_len = 0;
// 	if( data_pos + curr_len > (int) cap_head.data_end - (int) cap_head.data_begin )
// 		curr_len = cap_head.data_end - cap_head.data_begin - data_pos;

// 	// MSG( "data_pos: %d, curr_len: %d", data_pos, curr_len );

// 	lua_pushinteger( L, data_pos );
// 	lua_pushinteger( L, curr_len );	

// 	return 2;	
// }

/* State is passed between secure storage and Lua
 * interpreter as strings. Lua has facilities to convert
 * to other data types that are supported
 */

static int luaE_setlocalstate( lua_State *L ) {

	TEE_Result res;	
	const char* key = luaL_checkstring(L, -2);
	const char* val = luaL_checkstring(L, -1);

	// MSG( "Key: %s %d - Val: %s %d", key, strlen(key),
					 				// val, strlen(val) );

	res = do_set_state( (unsigned char*) key, strlen(key),
			  		    (unsigned char*) val, strlen(val) );
	if( res != TEE_SUCCESS ) {
		luaL_error( L, "Do_set_state() error" );
	}

	return 0;
}

static int luaE_getlocalstate( lua_State *L ) {

	TEE_Result res;
	unsigned char val[STATE_SIZE] = "none";
	const char* key = luaL_checkstring(L, -1);

	// MSG( "Key: %s %d - Val: %s %d", key, strlen(key),
					 				// val, strlen( (char*) val) );

	res = do_get_state( (unsigned char*) key, val, sizeof(val) );
	if( res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND ) {
		luaL_error( L, "Do_get_state() error" );
	}

	// MSG( "Key: %s %d - Val: %s %d", key, strlen(key),
					 				// val, strlen( (char*) val) );
	
	lua_pushlstring( L, (const char*) val, strlen( (char*) val) );	

	return 1;
}

static const luaL_Reg ext_funcs[] = {
	/* POLICY - local */
	{ "getlocalstate", luaE_getlocalstate },
	// { "getdataoffset", luaE_getOffsetLen },
	{ "getgps", luaE_getgps },
	{ "gettime", luaE_getcurrtime },
	// { "getdeclassifydest", luaE_getdeclassifydest },
	
	/* POLICY - server */
	{ "getserverstate", luaE_getserverstate },
	{ "reportlocid", luaE_reportlocid },
	{ "checkpolicychange", luaE_checkpolicychange },

	/* ACTIONS - allow/deny are available through true/false */
	{ "setstate", luaE_setlocalstate },
	{ "delete", luaE_deletefile },
	
	{ NULL, NULL }
};

TEE_Result add_lua_ext( lua_State *L ) {
	const luaL_Reg *lib;
	for( lib = ext_funcs; lib->func; lib++ ) {
		lua_pushcfunction( L, lib->func );
		lua_setglobal( L, lib->name );
	}
	return TEE_SUCCESS;
}
