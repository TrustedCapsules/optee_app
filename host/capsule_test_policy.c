#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>
#include <capsule.h>
#include <aes_keys.h>
#include "err_ta.h"
#include "key_data.h"
#include "capsule_command.h"

TEEC_Result change_policy_test() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/policychange.capsule";
	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "change_policy_test: initializeContext() failed" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "change_policy_test: allocateSharedMem() failed" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "change_policy_test: allocateSharedMem() failed" );

	
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "change_policy_test: openSession() failed" );
	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "change_policy_test: capsule_open() failed" );

	res = closeSession( &sess );
	CHECK_RESULT( res, "change_policy_test: closeSession() failed" );
	
	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "change_policy_test: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "change_policy_test: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "change_policy_test: finalizeContext() failed" );

	return res;
}

TEEC_Result remote_state_test() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/remotestate.capsule";
	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "remote_state_test: initializeContext() failed" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "remote_state_test: allocateSharedMem() failed" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "remote_state_test: allocateSharedMem() failed" );

	
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "remote_state_test: openSession() failed" );
	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "remote_state_test: capsule_open() failed" );
	
	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "remote_state_test: capsule_close() %s failed", 
				  capsule );

	res = closeSession( &sess );
	CHECK_RESULT( res, "remote_state_test: closeSession() failed" );
	
	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "remote_state_test: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "remote_state_test: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "remote_state_test: finalizeContext() failed" );

	return res;
}

TEEC_Result remote_reportlocid_test() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/reportlocid.capsule";
	char            read_cap[1024];
	int             pid = 12345;
	int             fd = 10;
	uint32_t        nr, nw, rlen = 1024;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "remote_reportlocid_test: initializeContext() failed" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "remote_reportlocid_test: allocateSharedMem() failed" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "remote_reportlocid_test: allocateSharedMem() failed" );

	
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "remote_reportlocid_test: openSession() failed" );

	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "remote_reportlocid_test: capsule_open() failed" );

	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "remote_reportlocid_test: capsule_read() failed" );

	res = capsule_write( &sess, &in_mem, read_cap, sizeof(read_cap), &nw, pid, fd );
	CHECK_RESULT( res, "remote_reportlocid_test: capsule_write() failed" );
	
	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "remote_reportlocid_test: capsule_close() %s failed", 
				  capsule );

	res = closeSession( &sess );
	CHECK_RESULT( res, "remote_reportlocid_test: closeSession() failed" );
	
	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "remote_reportlocid_test: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "remote_reportlocid_test: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "remote_reportlocid_test: finalizeContext() failed" );

	return res;
}

TEEC_Result remote_delete_test() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/remotedelete.capsule";
	int             fd_cap = 0;
	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "remote_delete_test: initializeContext() failed" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "remote_delete_test: allocateSharedMem() failed" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "remote_delete_test: allocateSharedMem() failed" );

	
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "remote_delete_test: openSession() failed" );

	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	if( res == TEE_SUCCESS ) {
		res = TEE_ERROR_NOT_SUPPORTED;	
		CHECK_RESULT( res, "remote_delete_test: capsule_open() should have failed" );
	}

	fd_cap = open( capsule, O_RDONLY );
	if( fd_cap >= 0 ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_RESULT( res, "remote_delete_test: capsule should be deleted" );
	}

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "remote_delete_test: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "remote_delete_test: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "remote_delete_test: finalizeContext() failed" );

	return res;
}

TEEC_Result local_delete_test() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/localdelete.capsule";
	int             fd_cap = 0;
	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "local_delete_test: initializeContext() failed" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "local_delete_test: allocateSharedMem() failed" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "local_delete_test: allocateSharedMem() failed" );

	
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "local_delete_test: openSession() failed" );

	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	if( res == TEE_SUCCESS ) {
		res = TEE_ERROR_NOT_SUPPORTED;	
		CHECK_RESULT( res, "local_delete_test: capsule_open() should have failed" );
	}

	fd_cap = open( capsule, O_RDONLY );
	if( fd_cap >= 0 ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_RESULT( res, "local_delete_test: capsule should be deleted" );
	}

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "local_delete_test: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "local_delete_test: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "local_delete_test: finalizeContext() failed" );

	return res;
}

TEEC_Result local_state_test() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/localstate.capsule";
	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "local_state_test: initializeContext() failed" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "local_state_test: allocateSharedMem() failed" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "local_state_test: allocateSharedMem() failed" );

	
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "local_state_test: openSession() failed" );

	
	/* Open once */
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "local_state_test: capsule_open() of capsule %s failed",
						capsule );

	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "local_state_test: capsule_close() %s failed", 
				  capsule );

	/* Open twice */
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "local_state_test: capsule_open() of capsule %s failed",
						capsule );

	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "local_state_test: capsule_close() %s failed", 
				  capsule );
	
	/* Third time should fail */
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	if( res == TEEC_SUCCESS ) {
		res = TEEC_ERROR_NOT_SUPPORTED;
		CHECK_RESULT( res, "local_state_test: capsule_open() %s should fail",
					capsule );
	}
	
	res = closeSession( &sess );
	CHECK_RESULT( res, "local_state_test: closeSession() failed" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "local_state_test: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "local_state_test: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "local_state_test: finalizeContext() failed" );

	return res;

}
TEEC_Result time_test() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/time.capsule";
	char            ptx[] = "/etc/other_capsules/time.data";
	FILE           *fp = NULL;
	uint32_t 		ns, nr, nw, i, rlen;
	char     		read_cap[1024];
	char            read_ptx[1024];
	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "time_test: initializeContext() failed" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "time_test: allocateSharedMem() failed" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "time_test: allocateSharedMem() failed" );

	
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "time_test: openSession() failed" );

	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "time_test: capsule_open() of capsule %s failed",
						capsule );


	fp = fopen( ptx, "rb" );
   	if( fp == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "time_test: fopen() of capsule ptx %s failed", 
					  ptx );
	}	

	/* Perform a read that should pass */	
	nr = 0;
	rlen = 1024;	
	
	res = capsule_lseek( &sess, 0, START, &ns, pid, fd );
	CHECK_RESULT( res, "time_test: capsule_lseek() pos %u failed", ns );
	
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "time_test: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );

	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	

	COMPARE_TEXT( 3, 1, i, read_cap, read_ptx, nr );
	
	/* Perform a write that should fail the policy check */
	res = capsule_write( &sess, &in_mem, read_cap, 
					     sizeof(read_cap), &nw, pid, fd );
	if( res == TEE_SUCCESS ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_RESULT( res, "time_test: capsule_write() %u B should have failed", 
						   sizeof(read_cap) );
	}
	
	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "time_test: capsule_close() %s failed", 
				  capsule );

	res = closeSession( &sess );
	CHECK_RESULT( res, "time_test: closeSession() failed" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "time_test: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "time_test: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "time_test: finalizeContext() failed" );

	return res;
}

TEEC_Result gps_test() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/gps.capsule";
	char            ptx[] = "/etc/other_capsules/gps.data";
	FILE           *fp = NULL;
	uint32_t 		ns, nr, nw, i, rlen;
	char     		read_cap[1024];
	char            read_ptx[1024];
	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "gps_test: initializeContext() failed" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "gps_test: allocateSharedMem() failed" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "gps_test: allocateSharedMem() failed" );

	
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "gps_test: openSession() failed" );

	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "gps_test: capsule_open() of capsule %s failed",
						capsule );


	fp = fopen( ptx, "rb" );
   	if( fp == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "gps_test: fopen() of capsule ptx %s failed", 
					  ptx );
	}	

	/* Perform a read that should pass */	
	nr = 0;
	rlen = 1024;	
	
	res = capsule_lseek( &sess, 0, START, &ns, pid, fd );
	CHECK_RESULT( res, "gps_test: capsule_lseek() pos %u failed", ns );
	
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "gps_test: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );

	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	

	COMPARE_TEXT( 3, 1, i, read_cap, read_ptx, nr );
	
	/* Perform a write that should fail the policy check */
	res = capsule_write( &sess, &in_mem, read_cap, 
					     sizeof(read_cap), &nw, pid, fd );
	if( res == TEE_SUCCESS ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_RESULT( res, "gps_test: capsule_write() %u B should have failed", 
						   sizeof(read_cap) );
	}
	
	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "gps_test: capsule_close() %s failed", 
				  capsule );

	res = closeSession( &sess );
	CHECK_RESULT( res, "gps_test: closeSession() failed" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "gps_test: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "gps_test: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "gps_test: finalizeContext() failed" );

	return res;

}

TEEC_Result cred_policy_test() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/credential.capsule";
	char            ptx[] = "/etc/other_capsules/credential.data";
	FILE           *fp = NULL;
	uint32_t 		ns, nr, i, rlen;
	char     		read_cap[1024];
	char            read_ptx[1024];
	char            val_random[STATE_SIZE] = {0x45,0x46,0x35,0x22,0x00};
	char            key[STATE_SIZE] = "cred";
	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "cred_policy_test: initializeContext() failed" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "cred_policy_test: allocateSharedMem() failed" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "cred_policy_test: allocateSharedMem() failed" );

	
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "cred_policy_test: openSession() failed" );

	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "cred_policy_test: capsule_open() of capsule %s failed",
						capsule );


	fp = fopen( ptx, "rb" );
   	if( fp == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "cred_policy_test: fopen() of capsule ptx %s failed", 
					  ptx );
	}	

	/* Perform a read that should pass */	
	nr = 0;
	rlen = 1024;	
	
	res = capsule_lseek( &sess, 0, START, &ns, pid, fd );
	CHECK_RESULT( res, "cred_policy_test: capsule_lseek() pos %u failed", ns );
	
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "cred_policy_test: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );

	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	

	COMPARE_TEXT( 3, 1, i, read_cap, read_ptx, nr );
	
	/* Perform a read that should fail the policy check */
	res = capsule_set_state( &sess, &in_mem, key, STATE_SIZE, 
							 val_random, STATE_SIZE, 
							 *(uint32_t*) (void*) capsule_data_array[7].id );	
	CHECK_RESULT( res, "cred_policy_test: capsule_set_state %s->%s failed",
					   key, val_random );

	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	if( res == TEE_SUCCESS ) {
		res = TEE_ERROR_NOT_SUPPORTED;
		CHECK_RESULT( res, "cred_policy_test: capsule_read() %u B of %u B at"
				       " pos %u should have failed", nr, rlen, ns );
	}
	
	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "cred_policy_test: capsule_close() %s failed", 
				  capsule );

	res = closeSession( &sess );
	CHECK_RESULT( res, "cred_policy_test: closeSession() failed" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "cred_policy_test: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "cred_policy_test: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "cred_policy_test: finalizeContext() failed" );

	return res;

}

int main(int argc, char *argv[]) {
	TEEC_Result res;
	
	res = cred_policy_test();
	CHECK_RESULT( res, "cred_policy_test: failed" );
	PRINT_INFO( "cred_policy_test: passed\n" );
	
	res = gps_test();
	CHECK_RESULT( res, "gps_test: failed" );
	PRINT_INFO( "gps_test: passed\n" );
	
	res = time_test();
	CHECK_RESULT( res, "time_test: failed" );
	PRINT_INFO( "time_test: passed\n" );
	
	res = local_state_test();
	CHECK_RESULT( res, "local_state_test: failed" );
	PRINT_INFO( "local_state_test: passed\n" );
	
	res = local_delete_test();
	CHECK_RESULT( res, "local_delete_test: failed" );
	PRINT_INFO( "local_delete_test: passed\n" );
	
	res = remote_delete_test();
	CHECK_RESULT( res, "remote_delete_test: failed" );
	PRINT_INFO( "remote_delete_test: passed\n" );
	
	res = remote_reportlocid_test();
	CHECK_RESULT( res, "remote_reportlocid_test: failed" );
	PRINT_INFO( "remote_reportlocid_test: passed\n" );
	
	res = remote_state_test();
	CHECK_RESULT( res, "remote_state_test: failed" );
	PRINT_INFO( "remote_state_test: passed\n" );

	res = change_policy_test();
	CHECK_RESULT( res, "change_policy_test: failed" );
	PRINT_INFO( "change_policy_test: passed\n" );
	return 0;

}
