#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <capsuleCommon.h>
#include <aes_keys.h>
#include <time.h>
#include <stdlib.h>
#include "err_ta.h"
#include "key_data.h"
#include "capsule_command.h"


// TODO: modify to take IP as argument instead of hardcoding it

/* 
 * Testing system-call layer networking with open(), read(), write(), close().
 * The server has to be on: 10.0.0.1/3490 and echo the test messages.
 * Test optee_os Panic handling TODOO separate out
 */
TEEC_Result test_01() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
#ifdef HIKEY
	char            ip[] = "198.162.52.26";
#else
	char            ip[] = "10.0.0.1";
#endif
	char            test_message[] = "Hello World! Who are you?";
	char            response_message[128];
	int             port = 3490, fd = -1;
	int             i;
	int             j;
	int             iterations = 10;
	int             nw; 
	int             nr;
	

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_01: initializeContext() failed" );

	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_01: allocateSharedMem() failed" );
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_01: allocateSharedMem() failed" );

	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_01: openSession() failed" );
	
	
	res = capsule_open_connection( &sess, &in_mem, ip, sizeof(ip),
								   port, &fd );
	CHECK_RESULT( res, "test_01: capsule_open_connection() failed" );
	

	for( i = 0; i < iterations; i++ ) {
		
		res = capsule_write_connection( &sess, &in_mem, test_message,
				                    sizeof( test_message ), fd, &nw );
		CHECK_RESULT( res, "test_01: capsule_write_connection() failed" );

		COMPARE_LEN( 1, 1, (int) sizeof(test_message), nw );
	
		res = capsule_read_connection( &sess, &out_mem, response_message,
					   				   sizeof( response_message ), fd, &nr );
		CHECK_RESULT( res, "test_01: capsule_read_connection() failed" );	

		COMPARE_LEN( 1, 1, nr, nw );

		COMPARE_TEXT( 1, 1, j, test_message, response_message, 
					  (int) sizeof(test_message) );
	}

	res = capsule_close_connection( &sess, fd );
	CHECK_RESULT( res, "test_01: capsule_close_connection() failed" );

	res = closeSession( &sess );
	CHECK_RESULT( res, "test_01: closeSession()" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_01: freeSharedMem()" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_01: freeSharedMem()" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_01: finalizeContext()" );

	return res;
	
}

/* 
 * Testing the encryption and serialization layer with bio capsule. 
 */
TEEC_Result test_02() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
#ifdef HIKEY
	char            ip[] = "198.162.52.26";
#else
	char            ip[] = "10.0.0.1";
#endif
	int             nr, nw;
    int            *send_id, send_op, send_rv;
	int             recv_id, recv_op, recv_plen, recv_rv;
	int             port = 3490, fd = -1;
	char 			capsule[] = "/etc/other_capsules/bio.capsule";		
	
	char            payload[] = "0123456789abcdefghijklmnopqrstuvwxyz"
							    "0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz";
    char            response[1024];								
	char            hash[HASH_LEN];	
	int             fake_pid = 12345, fake_fd = 10;

	srand(time(NULL));

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_02: initializeContext() failed" );

	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_02: allocateSharedMem() failed" );
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_02: allocateSharedMem() failed" );

	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_02: openSession() failed" );
	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), 
					    fake_pid, fake_fd );			
	CHECK_RESULT( res, "test_02: capsule_open() of capsule %s failed",
						capsule );	
	
	res = capsule_open_connection( &sess, &in_mem, ip, sizeof(ip),
								   port, &fd );
	CHECK_RESULT( res, "test_02: capsule_open_connection() failed" );

	send_id = (int*) (void*) capsule_data_array[0].id;
	send_op = REQ_TEST;	
	send_rv = rand(); 
	res = capsule_send( &sess, &in_mem, payload, 
					    sizeof(payload), send_op, send_rv, fd, &nw ); 	
	CHECK_RESULT( res, "test_02: capsule_send() failed" );

	res = capsule_recv_header( &sess, &out_mem, hash, HASH_LEN,
					           &recv_plen, &recv_id, &recv_op, &recv_rv, fd );
	CHECK_RESULT( res, "test_02: capsule_recv_header() failed" );	
	if( recv_op != RESP_TEST || recv_id != *send_id ||
		recv_plen != sizeof(payload) || recv_rv != send_rv ) {
		res = TEEC_ERROR_COMMUNICATION;
		CHECK_RESULT( res,  "test_02: capsule_recv_header() corrupted"
				            " op %d/%d, id 0x%08x/0x%08x, payload length"
				            " %d/%d, rvalue %d/%d", recv_op, send_op, 
							recv_id, *send_id, recv_plen, sizeof(payload), 
							recv_rv, send_rv );
	}

	res = capsule_recv_payload( &sess, &in_mem, &out_mem, 
								response, sizeof(response),
								hash, HASH_LEN, fd, &recv_plen );
	CHECK_RESULT( res, "test_2: capsule_recv_payload() corrupted" );
	COMPARE_TEXT( 2, 1, nr, payload, response, sizeof(payload) );	
	
	res = capsule_close_connection( &sess, fd );
	CHECK_RESULT( res, "test_02: capsule_close_connection() failed" );
	
	res = closeSession( &sess );
	CHECK_RESULT( res, "test_02: closeSession()" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_02: freeSharedMem()" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_02: freeSharedMem()" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_02: finalizeContext()" );

	return res;
	
}

/* 
 * Testing the encryption and serialization layer with short story capsule. 
 */
TEEC_Result test_03() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
#ifdef HIKEY
	char            ip[] = "198.162.52.26";
#else
	char            ip[] = "10.0.0.1";
#endif
	int             nr, nw;
    int            *send_id, send_op, send_rv;
	int             recv_id, recv_op, recv_plen, recv_rv;

	int             port = 3490, fd = -1;
	char 			capsule[] = "/etc/other_capsules/short_story.capsule";		
	
	char            payload[] = "0123456789abcdefghijklmnopqrstuvwxyz"
							    "0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz"
								"0123456789abcdefghijklmnopqrstuvwxyz";
    char            response[1024];								
	char            hash[HASH_LEN];	
	int			    fake_pid = 12345, fake_fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	srand(time(NULL));

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_03: initializeContext() failed" );

	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_03: allocateSharedMem() failed" );
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_03: allocateSharedMem() failed" );

	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_03: openSession() failed" );
	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), 
						fake_pid, fake_fd );			
	CHECK_RESULT( res, "test_03: capsule_open() of capsule %s failed",
						capsule );	
	
	res = capsule_open_connection( &sess, &in_mem, ip, sizeof(ip),
								   port, &fd );
	CHECK_RESULT( res, "test_03: capsule_open_connection() failed" );

	send_id = (int*) (void*) capsule_data_array[4].id;
	send_op = REQ_TEST;
	send_rv = rand();	
	res = capsule_send( &sess, &in_mem, payload, sizeof(payload), 
					    send_op, send_rv, fd, &nw ); 	
	CHECK_RESULT( res, "test_03: capsule_send() failed" );

	res = capsule_recv_header( &sess, &out_mem, hash, HASH_LEN,
					           &recv_plen, &recv_id, &recv_op, 
							   &recv_rv, fd );
	CHECK_RESULT( res, "test_03: capsule_recv_header() failed" );	
	if( recv_op != RESP_TEST || recv_id != *send_id ||
		recv_plen != sizeof( payload ) || recv_rv != send_rv ) {
		res = TEEC_ERROR_COMMUNICATION;
		CHECK_RESULT( res,  "test_03: capsule_recv_header() corrupted"
				            " op %d/%d, id 0x%08x/0x%08x, payload length"
				            " %d/%d, rvalue %d/%d", recv_op, send_op, 
							recv_id, *send_id, recv_plen, sizeof(payload),
				   			recv_rv, send_rv );
	}

	res = capsule_recv_payload( &sess, &in_mem, &out_mem, 
								response, sizeof(response),
								hash, HASH_LEN, fd, &recv_plen );
	CHECK_RESULT( res, "test_03: capsule_recv_payload() corrupted" );
	COMPARE_TEXT( 2, 1, nr, payload, response, sizeof(payload) );	
	
	res = capsule_close_connection( &sess, fd );
	CHECK_RESULT( res, "test_03: capsule_close_connection() failed" );
	
	res = closeSession( &sess );
	CHECK_RESULT( res, "test_03: closeSession()" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_03: freeSharedMem()" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_03: freeSharedMem()" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_03: finalizeContext()" );

	return res;
	
}
void print_usage() {
	PRINT_INFO( "USAGE: ./capsule_test_network MODE\n"
			    "  MODE -- ECHO | CAPSULE | ECHO_ENCRYPT_SERIALIZE\n" );
}

int main(int argc, char *argv[]) {
	
	TEEC_Result res;

	if( argc != 2 ) {
		print_usage();
		return 0;
	}

	if( strcmp( argv[1], "ECHO" ) == 0 ) {
		res = test_01();
		CHECK_RESULT( res, "test_01: failed" );
		PRINT_INFO( "test_01: passed\n" ); 		
	} else if( strcmp( argv[1], "ECHO_ENCRYPT_SERIALIZE" ) == 0 )   {
		res = test_02();
		CHECK_RESULT( res, "test_02: failed" );
		PRINT_INFO( "test_02: passed\n" );	
		
		res = test_03();
		CHECK_RESULT( res, "test_03: failed" );
		PRINT_INFO( "test_03: passed\n" );	
	} else {
		print_usage();
	}	
	
	
	return 0;
}
