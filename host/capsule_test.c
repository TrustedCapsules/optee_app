#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <capsule.h>
#include <aes_keys.h>
#include "err_ta.h"
#include "key_data.h"
#include "capsule_benchmark.h"
#include "capsule_command.h"

TEEC_Result test_13(void) {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Session 	sess;
	TEEC_Context 	ctx;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char            capsule1[] = "/etc/other_capsules/bio.capsule";
	char            capsule2[] = "/etc/other_capsules/short_story_copy.capsule";
	
	char            write_buf[] = "abcdefghij";
	char            read_buf[20];

	uint32_t        nr, nw, ns, i;

	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_13: initializeContext() failed\n" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_13: allocateSharedMem() failed\n" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_13: allocateSharedMem() failed.\n" );

	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_13: openSession() failed\n" );
	
	res = capsule_open( &sess, &in_mem, capsule1, sizeof(capsule1), 
						pid, fd );
	CHECK_RESULT( res, "test_13: capsule_open() of capsule %s"
				  	   " failed\n", capsule1 );

	res = capsule_ftruncate( &sess, 0 );
	
	res = capsule_open( &sess, &in_mem, capsule1, sizeof(capsule1), 
					    pid, fd + 1 );
	CHECK_RESULT( res, "test_13: capsule_open() of capsule %s failed", 
					  capsule1 );
			
	res = capsule_close( &sess, pid, fd + 1 );
	CHECK_RESULT(res, "test_13: capsule_close() %s failed", capsule1);
	

	res = capsule_write( &sess, &in_mem, write_buf, sizeof(write_buf),
				     	 &nw, pid, fd );
	CHECK_RESULT( res, "test_13: capsule_write() %u B of %u B at"
				   	   " pos %u failed for %s", nw, sizeof(write_buf),
					   0, capsule1 );
	
	res = capsule_lseek( &sess, 0, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_13: capsule_lseek() pos %u failed for %s",
						ns, capsule1 );

	res = capsule_read( &sess, &out_mem, read_buf, sizeof(write_buf), 
					    &nr, pid, fd );
	CHECK_RESULT( res, "test_13: capsule_read() %u B of %u B at"
					   " pos %u failed for %s", nr, sizeof(write_buf),
					   ns, capsule1 );

	COMPARE_TEXT( 13, 1, i, read_buf, write_buf, nr );

	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT(res, "test_13: capsule_close() %s failed", capsule1);
			
	res = closeSession( &sess );
	CHECK_RESULT( res, "test_13: closeSession() failed\n" );

	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_13: openSession() failed\n" );
	
	res = capsule_open( &sess, &in_mem, capsule2, sizeof(capsule2), 
						pid, fd );
	CHECK_RESULT( res, "test_13: capsule_open() of capsule %s"
				       " failed\n", capsule2 );
	
	res = capsule_ftruncate( &sess, 0 );
	
	res = capsule_open( &sess, &in_mem, capsule2, sizeof(capsule2), 
					    pid, fd + 1 );
	CHECK_RESULT( res, "test_13: capsule_open() of capsule %s failed", 
					  capsule2 );
			
	res = capsule_close( &sess, pid, fd + 1 );
	CHECK_RESULT(res, "test_13: capsule_close() %s failed", capsule2);
	

	res = capsule_write( &sess, &in_mem, write_buf, sizeof(write_buf),
				     	 &nw, pid, fd );
	CHECK_RESULT( res, "test_13: capsule_write() %u B of %u B at"
				   	   " pos %u failed for %s", nw, sizeof(write_buf),
					   0, capsule2 );
	
	res = capsule_lseek( &sess, 0, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_13: capsule_lseek() pos %u failed for %s",
						ns, capsule2 );

	res = capsule_read( &sess, &out_mem, read_buf, sizeof(write_buf), 
					    &nr, pid, fd );
	CHECK_RESULT( res, "test_13: capsule_read() %u B of %u B at"
					   " pos %u failed for %s", nr, sizeof(write_buf),
					   ns, capsule2 );

	COMPARE_TEXT( 13, 2, i, read_buf, write_buf, nr );

	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT(res, "test_13: capsule_close() %s failed", capsule2);

	res = closeSession( &sess );
	CHECK_RESULT( res, "test_13: closeSession() failed\n" );
	
	return res;
}

TEEC_Result test_12(void) {

	TEEC_Result     res = TEEC_SUCCESS;

	TEEC_Session 	sess;
	TEEC_Context 	ctx;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char            capsule1[] = "/etc/other_capsules/bio.capsule";
	char            reg_file1[] = "/etc/other_capsules/bio.data";
	char            capsule2[] = "/etc/other_capsules/short_story_copy.capsule";
	char            reg_file2[] = "/etc/other_capsules/short_story_copy.data";
	int             pid = 12345;
	int             fd = 10;
	uint32_t        data_size; 
	struct stat 	st;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_12: initializeContext() failed\n" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_12: allocateSharedMem() failed\n" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_12: allocateSharedMem() failed.\n" );

	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_12: openSession() failed\n" );
	
	res = capsule_open( &sess, &in_mem, capsule1, sizeof(capsule1), pid, fd );
	CHECK_RESULT( res, "test_12: capsule_open() of capsule %s failed\n", capsule1 );

	res = capsule_fstat( &sess, pid, fd, &data_size );
	CHECK_RESULT( res, "test_12: capsule_fstat() failed\n" );

	if( stat( reg_file1, &st ) != 0 ) {
		CHECK_RESULT( TEE_ERROR_NOT_SUPPORTED, "test_12: no %s found\n", 
					                           reg_file1 );
	}	

	if( data_size != st.st_size ) {
		CHECK_RESULT( TEE_ERROR_NOT_SUPPORTED, "test_12: capsule_fstat() %u"
					  " does not match stat() %jd\n", data_size, st.st_size );
	}

	res = closeSession( &sess );
	CHECK_RESULT( res, "test_12: closeSession() failed\n" );

	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_12: openSession() failed\n" );
	
	res = capsule_open( &sess, &in_mem, capsule2, sizeof(capsule2), pid, fd );
	CHECK_RESULT( res, "test_12: capsule_open() of capsule %s failed\n", capsule2 );

	res = capsule_fstat( &sess, pid, fd, &data_size );
	CHECK_RESULT( res, "test_12: capsule_fstat() failed\n" );

	if( stat( reg_file2, &st ) != 0 ) {
		CHECK_RESULT( TEE_ERROR_NOT_SUPPORTED, "test_12: no %s found\n", reg_file2 );
	}	

	if( data_size != st.st_size ) {
		CHECK_RESULT( TEE_ERROR_NOT_SUPPORTED, "test_12: capsule_fstat() %u"
					  " does not match stat() %u\n", data_size, st.st_size );
	}

	res = closeSession( &sess );
	CHECK_RESULT( res, "test_12: closeSession() failed\n" );
	
	return res;
}

TEEC_Result test_11(void) {
	char			capsule[100];

	// Start infinite loop. Need counter to see how many capsules
	// Also need way to catch out of memory exception. That way it can
	// Print the number of capsules. --> Would check res work?
	int count = 0;
	TEEC_Result     res = TEEC_SUCCESS;

	TEEC_Context 	ctx;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_11: initializeContext() failed. Count: %d\n", count );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_11: allocateSharedMem() failed. Count: %d\n", count );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_11: allocateSharedMem() failed. Count: %d\n", count );

	// Can't open more than one session?
	int i = 0;
	while (1) {
		// if (count % 10 == 0) {
		// 	printf("count: %d\n", count);
		// }
		memset( capsule, 0, sizeof(capsule) );
		strcpy( capsule, "/etc/" );
		strcat( capsule, (char*) capsule_data_array[i].str );
		strcat( capsule, ".capsule" );	

		printf("Testing memory with %s\n", capsule);

		TEEC_Session 	sess;
		res = openSession( &ctx, &sess, &uuid );
		CHECK_RESULT( res, "test_11: openSession() failed. Count: %d\n", count );
		res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
		CHECK_RESULT( res, "test_11: capsule_open() of capsule %s failed. Count: %d\n",
							capsule, count );
		// res = closeSession( &sess );
		// CHECK_RESULT( res, "test_11: closeSession() failed. Count: %d\n", count );
		i = (i+1) % (sizeof(capsule_data_array)/sizeof(struct capsule_data));
		count++;
	}

	return res;
}

/* Test the test_* capsules by reading/writing to them */
TEEC_Result test_10() {
	TEEC_Result		res = TEEC_SUCCESS;
	TEEC_Context	ctx;
	TEEC_Session	sess;
	TEEC_UUID		uuid = CAPSULE_UUID;
	char			capsule[100];
	uint32_t		ns, nr, i, nw;
	char			buf[1024];
	int				pid = 12345;
	int				fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx );
	CHECK_RESULT( res, "test_10: initializeContext() failed" );

	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_10: allocateSharedMem() failed" );

	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_10: allocateSharedMem() failed" );


	for( i = 16; i < sizeof( capsule_data_array ) / 
					 sizeof( struct capsule_data ); i++ ) {
	
		res = openSession( &ctx, &sess, &uuid );
		CHECK_RESULT( res, "test_10: openSession() failed" );
		
		memset( capsule, 0, sizeof(capsule) );
		strcpy( capsule, "/etc/" );
		strcat( capsule, (char*) capsule_data_array[i].str );
		strcat( capsule, ".capsule" );	
		
		if( access( capsule, F_OK ) != -1 ) {
		
			res = capsule_open( &sess, &in_mem, capsule, 
							    sizeof(capsule), pid, fd );
			CHECK_RESULT( res, "test_10: capsule_open() of capsule %s failed", 
						  capsule );

			nr = 0;
			res = capsule_lseek( &sess, 1024, START, &ns, pid, fd );
			CHECK_RESULT( res, "test_10: capsule_lseek() pos %u failed for %s", 
							   ns, capsule );

			res = capsule_read( &sess, &out_mem, buf, sizeof(buf), &nr, pid, fd );
			CHECK_RESULT( res, "test_10: capsule_read() %u B of %u B at"
							   " pos %u failed for %s", nr, sizeof(buf), ns, 
							   capsule );
		
			nw = 0;
			res = capsule_lseek( &sess, 1024, START, &ns, pid, fd );
			CHECK_RESULT( res, "test_10: capsule_lseek() pos %u failed for %s", 
						   ns, capsule );
	
			res = capsule_write( &sess, &in_mem, buf, nr, &nw, pid, fd );
			CHECK_RESULT( res, "test_10: capsule_write() %u B of %u B at"
					   	   " pos %u failed for %s", nw, nr, ns, capsule );
		
			res = capsule_close( &sess, pid, fd );
			CHECK_RESULT( res, "test_10: capsule_close() %s failed",
						  capsule );
			
			res = capsule_open( &sess, &in_mem, capsule, 
							    sizeof(capsule), pid, fd );
			CHECK_RESULT( res, "test_10: capsule_open() of capsule %s failed", 
						  capsule );
			
			res = capsule_close( &sess, pid, fd );
			CHECK_RESULT( res, "test_10: capsule_close() %s failed",
						  capsule );
		}
		
		res = closeSession( &sess );
		CHECK_RESULT( res, "test_10: closeSession() failed" );
	}


	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_10: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_10: freeSharedMem () out_mem failed" );

	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_10: finalizeContext() failed" );

	return res;

}
/* Test the redaction feature */
TEEC_Result test_09() {
	TEEC_Result		res = TEEC_SUCCESS;
	TEEC_Context	ctx;
	TEEC_Session	sess;
	TEEC_UUID		uuid = CAPSULE_UUID;
	char			capsule[] = "/etc/other_capsules/bio_redact.capsule";
	uint32_t		ns, nr, i, rlen;
	char			read_cap[1024];
	char			redact1[] = "###e: Pet#r Chen\n" //16 --> 0 based byte count
								"Age: 25\n" //24
								"Gender: Male\n" //37
								"Address: 1234 High Park Avenue, Baltimore, ###" //83
								"#####ation: Stud####" //103
								"###############" // 118
								"##############"; //132
	char           *redact2, *redact3;
	int				pid = 12345;
	int				fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx );
	CHECK_RESULT( res, "test_09: initializeContext() failed" );

	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_09: allocateSharedMem() failed" );

	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_09: allocateSharedMem() failed" );

	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_09: openSession() failed" );

	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "test_09: capsule_open() of capsule %s failed", 
						capsule );


	/* Read the entire file from offset 0. Read length larger than the
	 * file */

	nr = 0;
	rlen = 512;

	res = capsule_lseek( &sess, 0, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_09: capsule_lseek() pos %u failed", ns );

	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_09: capsule_read() %u B of %u B at"
					   " pos %u failed", nr, rlen, ns );

	COMPARE_TEXT( 9, 1, i, read_cap, redact1, nr );
	
	/* Read offset into  file from. Read less than length of the file */
	nr = 0;
	rlen = 20;
	redact2 = redact1 + 10;

	res = capsule_lseek( &sess, 10, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_09: capsule_lseek() pos %u failed", ns );

	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_09:capsule_read() %u B of %u B at"
					   "pos %u failed", nr, rlen, ns );

	COMPARE_TEXT( 9, 2, i, read_cap, redact2, nr );

	/* Read offset into  file from. Read more than length of the file */
	nr = 0;
	rlen = 200;
	redact3 = redact1 + 20;

	res = capsule_lseek( &sess, 20, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_09: capsule_lseek() pos %u failed", ns );

	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_09:capsule_read() %u B of %u B at"
					   "pos %u failed", nr, rlen, ns );


	COMPARE_TEXT( 9, 3, i, read_cap, redact3, nr );
	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "test_09: capsule_close() %s failed",
				  capsule );

	res = closeSession( &sess );
	CHECK_RESULT( res, "test_09: closeSession() failed" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_09: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_09: freeSharedMem () out_mem failed" );

	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_09: finalizeContext() failed" );

	return res;

}

/* Change the policy on a capsule */
TEEC_Result test_08() {
	TEEC_Result		res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session	sess1;
	TEEC_Session    sess2;
	TEEC_UUID       uuid = CAPSULE_UUID;
	FILE           *fp_orig;
	FILE           *fp_created;
	char            buf_orig[1024];
	char            buf_created[1024];
	int             nr_orig, nr_created, i;
	char 			capsule1[] = "/etc/other_capsules/bio_copy.capsule";
	char            policy1[] = "/etc/other_capsules/short_story_copy.policy";
	char            compare1[] = "/etc/other_capsules/bio_policy.capsule";
	char            capsule2[] = "/etc/other_capsules/short_story_copy.capsule";
	char            policy2[] = "/etc/other_capsules/bio_copy.policy";
	char            compare2[] = "/etc/other_capsules/short_story_policy.capsule";
	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_08: initializeContext() failed" );

	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_08: allocateSharedMem() failed" );
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_08: allocateSharedMem() failed" );

	res = openSession( &ctx, &sess1, &uuid );
	CHECK_RESULT( res, "test_08: openSession() sess1 failed" );

	/* We write a policy that is longer than the current policy */
	res = capsule_open( &sess1, &in_mem, capsule1, sizeof(capsule1), pid, fd );
	CHECK_RESULT( res, "test_08: capsule_open() of capsule %s failed",
						capsule1 );

	res = capsule_change_policy( &sess1, &in_mem, policy1, 
								 sizeof(policy1) );
	CHECK_RESULT( res, "test_08: capsule_change_policy() failed" );

	fp_orig = fopen( compare1, "r+" );
   	if( fp_orig == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_08: fopen() of capsule ptx %s failed", 
					  compare1 );
	}
	/* skip the header */
	fseek( fp_orig, sizeof( struct TrustedCap ), SEEK_SET );


	fp_created = fopen( capsule1, "r+" );
   	if( fp_created == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_08: fopen() of capsule ptx %s failed", 
					  capsule1 );
	}
	fseek( fp_created, sizeof( struct TrustedCap ), SEEK_SET );
	
	do { 
		nr_orig = fread( buf_orig, sizeof(char), sizeof(buf_orig), 
						 fp_orig );

		nr_created = fread( buf_created, sizeof(char), 
							sizeof(buf_created), fp_created );

		if( nr_orig != nr_created ) {
			CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
				"test_08: Part 1 length of the two files do not match."
				" Original: %d, Created: %d", nr_orig, nr_created );
		}

		COMPARE_CAPSULE( 8, 1, i, buf_orig, buf_created, nr_orig );
	} while( nr_orig != 0 || nr_created != 0 ); 
	
	fclose( fp_orig );
	fclose( fp_created );

	res = capsule_close( &sess1, pid, fd );
	CHECK_RESULT( res, "test_08: capsule_close() %s failed", 
				       capsule1 );

	res = capsule_open( &sess1, &in_mem, capsule1, sizeof(capsule1), pid, fd );
	CHECK_RESULT( res, "test_08: capsule_open() of capsule %s failed",	 	
   					capsule1 );
	
	res = capsule_close( &sess1, pid, fd );
	CHECK_RESULT( res, "test_08: capsule_close() %s failed", 
				       capsule1 );
	
	res = openSession( &ctx, &sess2, &uuid );
	CHECK_RESULT( res, "test_08: openSession() sess2 failed" );
	
	/* Change the capsule policy to a new policy that is shorter */
	res = capsule_open( &sess2, &in_mem, capsule2, sizeof(capsule2), pid, fd );
	CHECK_RESULT( res, "test_08: capsule_open() of capsule %s failed",
						capsule2 );

	res = capsule_change_policy( &sess2, &in_mem, policy2, 
					             sizeof(policy2) );
	CHECK_RESULT( res, "test_08: capsule_create() failed" );

	fp_orig = fopen( compare2, "r+" );
   	if( fp_orig == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_08: fopen() of capsule ptx %s failed", 
					  compare2 );
	}
	fseek( fp_orig, sizeof( struct TrustedCap ), SEEK_SET );

	fp_created = fopen( capsule2, "r+" );
   	if( fp_created == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_08: fopen() of capsule ptx %s failed", 
					  capsule2 );
	}
	fseek( fp_created, sizeof( struct TrustedCap ), SEEK_SET );

	do { 
		nr_orig = fread( buf_orig, sizeof(char), sizeof(buf_orig), 
						 fp_orig );
		nr_created = fread( buf_created, sizeof(char), 
							sizeof(buf_created), fp_created );
		
		if( nr_orig != nr_created ) {
			CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
				"test_08: Part 2 length of the two files do not match."
				" Original: %d, Created: %d", nr_orig, nr_created );
		}

		COMPARE_CAPSULE( 8, 2, i, buf_orig, buf_created, nr_orig );
	} while( nr_orig != 0 || nr_created != 0 ); 
	
	fclose( fp_orig );
	fclose( fp_created );

	res = capsule_close( &sess2, pid, fd );
	CHECK_RESULT( res, "test_08: capsule_close() %s failed", 
				  capsule2 );

	res = capsule_open( &sess2, &in_mem, capsule2, sizeof(capsule2), pid, fd );
	CHECK_RESULT( res, "test_08: capsule_open() of capsule %s failed",
						capsule2 );
	
	res = capsule_close( &sess2, pid, fd );
	CHECK_RESULT( res, "test_08: capsule_close() %s failed", 
				  capsule2 );

	res = closeSession( &sess1 );
	CHECK_RESULT( res, "test_08: closeSession() sess1 failed" );
	
	res = closeSession( &sess2 );
	CHECK_RESULT( res, "test_08: closeSession() sess2 failed" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_08: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_08: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_08: finalizeContext() failed" );

	return res;
}

/* Encapsulate plaintext files */
TEEC_Result test_07() {
	TEEC_Result		res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session	sess1;
	TEEC_Session    sess2;
	TEEC_UUID       uuid = CAPSULE_UUID;
	FILE           *fp_orig;
	FILE           *fp_created;
	char            buf_orig[1024];
	char            buf_created[1024];
	int             nr_orig, nr_created, i;
	char 			capsule_small[] = "/etc/other_capsules/bio_copy.capsule";
	char            plt_small[] = "/etc/other_capsules/bio_copy.data";
	char            capsule_large[] = "/etc/other_capsules/short_story_copy.capsule";
	char            plt_large[] = "/etc/other_capsules/short_story_copy.data";
    int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_07: initializeContext() failed" );

	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_07: allocateSharedMem() failed" );
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_07: allocateSharedMem() failed" );

	res = openSession( &ctx, &sess1, &uuid );
	CHECK_RESULT( res, "test_07: openSession() sess1 failed" );

	/* Encapsulate a small capsule*/
	res = capsule_open( &sess1, &in_mem, capsule_small, 
					 	sizeof(capsule_small), pid, fd );
	CHECK_RESULT( res, "test_07: capsule_open() of capsule %s failed",
						capsule_small );

	res = capsule_create( &sess1, &in_mem, plt_small, 
						  sizeof(plt_small) );
	CHECK_RESULT( res, "test_07: capsule_create() failed" );

	fp_orig = fopen( capsule_small, "r+" );
   	if( fp_orig == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_07: fopen() of capsule ptx %s failed", 
					  capsule_small );
	}

	fp_created = fopen( plt_small, "r+" );
   	if( fp_created == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_07: fopen() of capsule ptx %s failed", 
					  plt_small );
	}

	do { 
		nr_orig = fread( buf_orig, sizeof(char), sizeof(buf_orig), 
						 fp_orig );
		nr_created = fread( buf_created, sizeof(char), 
							sizeof(buf_created), fp_created );
		
		if( nr_orig != nr_created ) {
			CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
				"test_07: part 1 length of the two files do not match."
				" Original: %d, Created: %d", nr_orig, nr_created );
		}

		COMPARE_CAPSULE( 7, 1, i, buf_orig, buf_created, nr_orig );
	} while( nr_orig != 0 || nr_created != 0 ); 
	
	fclose( fp_orig );
	fclose( fp_created );

	res = capsule_close( &sess1, pid, fd );
	CHECK_RESULT( res, "test_07: capsule_close() %s failed", 
				  capsule_small );
	
	res = openSession( &ctx, &sess2, &uuid );
	CHECK_RESULT( res, "test_07: openSession() sess2 failed" );

	/* Encapsulate a large capsule*/
	res = capsule_open( &sess2, &in_mem, capsule_large, 
					 	sizeof(capsule_large), pid, fd );
	CHECK_RESULT( res, "test_07: capsule_open() of capsule %s failed",
						capsule_large );

	res = capsule_create( &sess2, &in_mem, plt_large, 
						  sizeof(plt_large) );
	CHECK_RESULT( res, "test_07: capsule_create() failed" );

	fp_orig = fopen( capsule_large, "r+" );
   	if( fp_orig == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_07: fopen() of capsule ptx %s failed", 
					  capsule_large );
	}

	fp_created = fopen( plt_large, "r+" );
   	if( fp_created == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_07: fopen() of capsule ptx %s failed", 
					  plt_large );
	}

	do { 
		nr_orig = fread( buf_orig, sizeof(char), sizeof(buf_orig), 
						 fp_orig );
		nr_created = fread( buf_created, sizeof(char), 
							sizeof(buf_created), fp_created );
		
		if( nr_orig != nr_created ) {
			CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
				"test_07: part 2 length of the two files do not match."
				" Original: %d, Created: %d", nr_orig, nr_created );
		}

		COMPARE_CAPSULE( 7, 2, i, buf_orig, buf_created, nr_orig );
	} while( nr_orig != 0 || nr_created != 0 ); 
	
	fclose( fp_orig );
	fclose( fp_created );

	res = capsule_close( &sess2, pid, fd );
	CHECK_RESULT( res, "test_07: capsule_close() %s failed", 
				  capsule_large );

	res = closeSession( &sess1 );
	CHECK_RESULT( res, "test_07: closeSession() sess1 failed" );
	
	res = closeSession( &sess2 );
	CHECK_RESULT( res, "test_07: closeSession() sess2 failed" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_07: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_07: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_07: finalizeContext() failed" );

	return res;
}

/* Write test of a large capsule file that > 1 chunk */
TEEC_Result test_06() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/short_story.capsule";
	char            ptx[] = "/etc/other_capsules/short_story.data";
	FILE           *fp = NULL;
	uint32_t 		ns, nr, nw, i, rlen, wlen;
	char     		read_cap[1024];
	char            read_ptx[1024];
	char     		buf[] = "abcdefghijklmnopqrstuvwxyz1234567890\n"
					    	"abcdefghijklmnopqrstuvwxyz1234567890\n"
 					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   	 	"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   	    "abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n";
	int              pid = 12345;
	int              fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_06: initializeContext() failed" );

	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_06: allocateSharedMem() failed" );
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_06: allocateSharedMem() failed" );

	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_06: openSession() failed" );

	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "test_06: capsule_open() of capsule %s failed",
						capsule );

	fp = fopen( ptx, "r+" );
   	if( fp == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_06: fopen() of capsule ptx %s failed", 
					  ptx );
	}	

	/* Write a small piece of data in the middle of file. Verify with
	 * a small read (1 chunk). */
	nw = 0;
	wlen = 8;
	
   	res = capsule_lseek( &sess, 46, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_06: capsule_lseek() pos %u failed", ns );
	res = capsule_write( &sess, &in_mem, buf, wlen, &nw, pid, fd );
	CHECK_RESULT( res, "test_06: capsule_write() %u B of %u B at"
					   " pos %u failed", nw, wlen, ns );

	ns = fseek( fp, ns, SEEK_SET );
	nw = fwrite( buf, sizeof(char), wlen, fp ); 

	nr = 0;
	rlen = 14;	
	
	res = capsule_lseek( &sess, 40, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_06: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_06: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );
	
	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	
	
	COMPARE_TEXT( 6, 1, i, read_cap, read_ptx, nr );

	/* Perform a large write (>1 chunk) at the end of the file. Verify	
	 * with a large read across two chunks in the middle of the file */
	nw = 0;
	wlen = 1000;
	res = capsule_lseek( &sess, 0, END, &ns, pid, fd );
	CHECK_RESULT( res, "test_06: capsule_lseek() pos %u failed", ns );
	res = capsule_write( &sess, &in_mem, buf, wlen, &nw, pid, fd );
	CHECK_RESULT( res, "test_06: capsule_write() %u B of %u B at"
					   " pos %u failed", nw, wlen, ns );
	
	ns = fseek( fp, ns, SEEK_END );
	nw = fwrite( buf, sizeof(char), wlen, fp ); 
	
	nr = 0;
	rlen = 600;
	
	res = capsule_lseek( &sess, 800, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_06: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_06: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );
	
	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	

	COMPARE_TEXT( 6, 2, i, read_cap, read_ptx, nr );

	fclose( fp );

	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "test_06: capsule_close() %s failed", capsule );

	/* Reopen the capsule test */
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "test_06: capsule_open() of capsule %s failed",
						capsule );

	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "test_06: capsule_close() %s failed", capsule );
	
	res = closeSession( &sess );
	CHECK_RESULT( res, "test_06: closeSession() failed" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_06: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_06: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_06: finalizeContext() failed" );

	return res;
}

/* Write test of a small capsule file that < 1 chunk */
TEEC_Result test_05() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/bio.capsule";
	char            ptx[] = "/etc/other_capsules/bio.data";
	FILE           *fp = NULL;
	uint32_t 		ns, nr, nw, i, rlen, wlen;
	char     		read_cap[1024];
	char            read_ptx[1024];
	char     		buf[] = "abcdefghijklmnopqrstuvwxyz1234567890\n"
					    	"abcdefghijklmnopqrstuvwxyz1234567890\n"
 					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   	 	"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   	    "abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n"
					   		"abcdefghijklmnopqrstuvwxyz1234567890\n";
	int              pid = 12345;
	int              fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_05: initializeContext() failed" );

	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_05: allocateSharedMem() failed" );
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_05: allocateSharedMem() failed" );

	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_05: openSession() failed" );

	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "test_05: capsule_open() of capsule %s failed",
						capsule );

	fp = fopen( ptx, "r+" );
   	if( fp == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_05: fopen() of capsule ptx %s failed", 
					  ptx );
	}	

	/* Write a small piece of data in the middle of file. Then verify 
	   with a small read (1 chunk). */
	nw = 0;
	wlen = 8;
	
   	res = capsule_lseek( &sess, 46, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_lseek() pos %u failed", ns );
	res = capsule_write( &sess, &in_mem, buf, wlen, &nw, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_write() %u B of %u B at"
					   " pos %u failed", nw, wlen, ns );

	ns = fseek( fp, ns, SEEK_SET );
	nw = fwrite( buf, sizeof(char), wlen, fp ); 

	nr = 0;
	rlen = 14;	
	
	res = capsule_lseek( &sess, 40, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );
	
	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	
	
	COMPARE_TEXT( 5, 1, i, read_cap, read_ptx, nr );

	/* Write a small piece of data to the end of the file. Then verify
	 * with a small read */
	
	nw = 0;
	wlen = 19;
	
   	res = capsule_lseek( &sess, 114, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_lseek() pos %u failed", ns );
	res = capsule_write( &sess, &in_mem, buf, wlen, &nw, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_write() %u B of %u B at"
					   " pos %u failed", nw, wlen, ns );

	ns = fseek( fp, ns, SEEK_SET );
	nw = fwrite( buf, sizeof(char), wlen, fp ); 

	nr = 0;
	rlen = 20;	
	
	res = capsule_lseek( &sess, 114, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );
	
	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	
	
	COMPARE_TEXT( 5, 2, i, read_cap, read_ptx, nr );
	
	/* Perform a large write (>1 chunk) at the end of the file
	 * that creates a file hole. Verify with a large read after
	 * the file hole and small read before. We also make a read 
	 * inside of the file hole, but do not verify as the contents 
	 * are garbage */	
	nw = 0;
	wlen = 1000;
	res = capsule_lseek( &sess, 3150, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_lseek() pos %u failed", ns );
	res = capsule_write( &sess, &in_mem, buf, wlen, &nw, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_write() %u B of %u B at"
					   " pos %u failed", nw, wlen, ns );
	
	ns = fseek( fp, ns, SEEK_SET );
	nw = fwrite( buf, sizeof(char), wlen, fp ); 
	
	nr = 0;
	rlen = 133;
	
	res = capsule_lseek( &sess, 0, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );

	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	
	
	COMPARE_TEXT( 5, 3, i, read_cap, read_ptx, nr );
	
	nr = 0;
	rlen = 1024;
	
	res = capsule_lseek( &sess, 131, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );
	
	res = capsule_lseek( &sess, 3150, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );

	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	
	
	COMPARE_TEXT( 5, 4, i, read_cap, read_ptx, nr );

	/* Reopen the capsule test */
	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_close() %s failed", capsule );
	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "test_05: capsule_open() re-open of capsule %s failed",
						capsule );
	
	fclose( fp );

	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "test_05: capsule_close() %s failed", 
				  capsule );

	res = closeSession( &sess );
	CHECK_RESULT( res, "test_05: closeSession() failed" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_05: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_05: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_05: finalizeContext() failed" );

	return res;
}

/* Read test of a large capsule file that > 1 chunk */
TEEC_Result test_04() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/short_story.capsule";
	char 			ptx[] = "/etc/other_capsules/short_story.data";
	FILE           *fp = NULL;
	uint32_t 		ns, nr, i, rlen;
	char     		read_cap[1024];
	char            read_ptx[1024];
	int             pid = 12345;
	int             fd = 10;
	
	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_04: initializeContext() failed" );

	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_04: allocateSharedMem() failed" );
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_04: allocateSharedMem() failed" );

	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_04: openSession() failed" );

	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "test_04: capsule_open() of capsule %s failed",
						capsule );
			
	fp = fopen( ptx, "rb" );
   	if( fp == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_04: fopen() of capsule ptx %s failed", 
					  ptx );
	}	

	/* Perform a read that is larger than the file */	
	nr = 0;
	rlen = 34;	
	
	res = capsule_lseek( &sess, 0, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_04: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_04: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );

	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	
	
	COMPARE_TEXT( 4, 1, i, read_cap, read_ptx, nr );
	
	/* Peform a read (>1 chunk) in the middle of the file */
	nr = 0;
	rlen = 512;	
	
	res = capsule_lseek( &sess, 700, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_04: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_04: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );
	
	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	
	
	COMPARE_TEXT( 4, 2, i, read_cap, read_ptx, nr );

	/*Peform a large read (>1 chunk) in the middle of the file */
	nr = 0;
	rlen = 20;
	
	res = capsule_lseek( &sess, 0, END, &ns, pid, fd );
	CHECK_RESULT( res, "test_04: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_04: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );
	
	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	
	
	COMPARE_TEXT( 4, 3, i, read_cap, read_ptx, nr );

	fclose( fp );

	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "test_04: capsule_close() %s failed", 
				  capsule );

	res = closeSession( &sess );
	CHECK_RESULT( res, "test_04: closeSession() failed" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_04: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_04: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_04: finalizeContext() failed" );

	return res;

}

/* Read test of a small capsule file that is < 1 chunk */
TEEC_Result test_03() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	char 			capsule[] = "/etc/other_capsules/bio.capsule";
	char            ptx[] = "/etc/other_capsules/bio.data";
	FILE           *fp = NULL;
	uint32_t 		ns, nr, i, rlen;
	char     		read_cap[1024];
	char            read_ptx[1024];
	int             pid = 12345;
	int             fd = 10;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_03: initializeContext() failed" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_03: allocateSharedMem() failed" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_03: allocateSharedMem() failed" );

	
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "test_03: openSession() failed" );

	
	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
	CHECK_RESULT( res, "test_03: capsule_open() of capsule %s failed",
						capsule );

	res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd+1 );
	CHECK_RESULT( res, "test_03: capsule_open() of capsule %s failed",
						capsule );
	

	fp = fopen( ptx, "rb" );
   	if( fp == NULL ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "test_03: fopen() of capsule ptx %s failed", 
					  ptx );
	}	

	/* Perform a read that is larger than the file */	
	nr = 0;
	rlen = 512;	
	
	res = capsule_lseek( &sess, 0, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_03: capsule_lseek() pos %u failed", ns );
	
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_03: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );

	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	

	COMPARE_TEXT( 3, 1, i, read_cap, read_ptx, nr );
	
	/* Peform a small read (1 chunk) in the middle of the file */
	nr = 0;
	rlen = 100;	
	
	res = capsule_lseek( &sess, 10, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_03: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_03: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );
	
	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	
	
	COMPARE_TEXT( 3, 2, i, read_cap, read_ptx, nr );

	/*Peform a large read (>1 chunk) in the middle of the file */
	nr = 0;
	rlen = 600;
	
	res = capsule_lseek( &sess, 800, START, &ns, pid, fd );
	CHECK_RESULT( res, "test_03: capsule_lseek() pos %u failed", ns );
	res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
	CHECK_RESULT( res, "test_03: capsule_read() %u B of %u B at"
				       " pos %u failed", nr, rlen, ns );
	
	ns = fseek( fp, ns, SEEK_SET );	
	nr = fread( read_ptx, sizeof(char), rlen, fp );	
	
	COMPARE_TEXT( 3, 3, i, read_cap, read_ptx, nr );

	fclose( fp );

	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "test_03: capsule_close() %s failed", 
				  capsule );

	res = capsule_close( &sess, pid, fd+1 );
	CHECK_RESULT( res, "test_03: capsule_close() %s failed", 
				  capsule );
	
	res = closeSession( &sess );
	CHECK_RESULT( res, "test_03: closeSession() failed" );

	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_03: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_03: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_03: finalizeContext() failed" );

	return res;

}

/* Register AES keys and credentials with the TA */
TEEC_Result test_02() {

	char 		key[STATE_SIZE] = "cred";
	char        val[STATE_SIZE];
	char        key_random[STATE_SIZE] = "num_access";
	char        val_random[STATE_SIZE] = "0";
	char		key_doct[STATE_SIZE] = "doctor";
	char		val_doct[STATE_SIZE] = "doc1";
	char		key_insu[STATE_SIZE] = "insurer";
	char		val_insu[STATE_SIZE] = "ins1";
	char        val_get[STATE_SIZE];
	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess;
	TEEC_UUID    	uuid = CAPSULE_UUID;
	int             i;

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

	/* Test key registration */

	for( i = 0; i < sizeof( capsule_data_array ) /
					sizeof( struct capsule_data ); i++ ) {
		res = register_aes_key( &sess, capsule_data_array[i].id,
						 		key_std, sizeof(key_std),
								iv_std, sizeof(iv_std), 
								capsule_data_array[i].chunk_size,
								&in_mem );
		CHECK_RESULT( res, "test_02: register_aes_key() %s failed", 
						   capsule_data_array[i].str );
	}

	for( i = 0; i < sizeof( capsule_data_array ) /
					sizeof( struct capsule_data ); i++ ) {
		// set cred state to wrong value
		res = capsule_set_state( &sess, &in_mem, key, STATE_SIZE, 
								 val_random, STATE_SIZE, 
								 *(uint32_t*) (void*) capsule_data_array[i].id );
		CHECK_RESULT( res, "test_02: capsule_set_state() key %s -> val %s"
						   " for %s failed", key, val_random, 
						   capsule_data_array[i].str );

		// reset the cred state to the right value
		memset( val, 0, sizeof(val) );
		memcpy( val, capsule_data_array[i].cred, 
				sizeof( capsule_data_array[i].cred ) );
		
		res = capsule_set_state( &sess, &in_mem, key, STATE_SIZE,
								 val, STATE_SIZE, 
								 *(uint32_t*) (void*) capsule_data_array[i].id );
		CHECK_RESULT( res, "test_02: capsule_set_state() key %s -> val %s"
						   " for %s failed", key, val, capsule_data_array[i].str );
		
		// setting another random state to see if we can add multiple
		// states 
		res = capsule_set_state( &sess, &in_mem, key_random, STATE_SIZE,
								 val_random, STATE_SIZE, 
								 *(uint32_t*) (void*) capsule_data_array[i].id );
		CHECK_RESULT( res, "test_02: capsule_set_state() key %s -> val %s"
						   " for %s failed", key_random, val_random, 
						   capsule_data_array[i].str );

		// get the two states to see if they are correct 
		res = capsule_get_state( &sess, &in_mem, &out_mem, key, STATE_SIZE, 
							 	 val_get, STATE_SIZE, 
								 *(uint32_t*) (void*) capsule_data_array[i].id );
		CHECK_RESULT( res, "test_02: capsule_get_state() key %s failed for %s", 
					   	   key, capsule_data_array[i].str );

		if( strcmp( val, val_get) != 0 ) {
			CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT, 
						 "test_02: capsule state op for key %s results did "
						 " not match (%s) (%s)", key, val, val_get );
		}
	
		res = capsule_get_state( &sess, &in_mem, &out_mem, key_random, 
								 STATE_SIZE, val_get, STATE_SIZE, 
								 *(uint32_t*) (void*) capsule_data_array[i].id );
		CHECK_RESULT( res, "test_02: capsule_get_state() key %s failed for %s", 
					   	   key_random, capsule_data_array[i].str );

		if( strcmp( val_random, val_get) != 0 ) {
			CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT, 
						 "test_02: capsule state op for key %s results did "
						 " not match (%s) (%s)", key_random, val_random, val_get );
		}
	}

	res = capsule_set_state( &sess, &in_mem, key_doct, STATE_SIZE, 
							val_doct, STATE_SIZE,
							*(uint32_t*) (void*) capsule_data_array[32].id );
	res = capsule_set_state( &sess, &in_mem, key_insu, STATE_SIZE, 
							val_insu, STATE_SIZE,
							*(uint32_t*) (void*) capsule_data_array[32].id);

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


/* Tests allocation of shared memory and initialization
 * of a context and session */
TEEC_Result test_01() {

	TEEC_Result     res = TEEC_SUCCESS;
	TEEC_Context 	ctx;
	TEEC_Session 	sess1;
	TEEC_Session    sess2;
	TEEC_UUID    	uuid = CAPSULE_UUID;

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };

	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "test_01: initializeContext() failed" );

	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "test_01: allocateSharedMem() failed");
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "test_01: allocateSharedMem() failed");

	res = openSession( &ctx, &sess1, &uuid );
	CHECK_RESULT( res, "test_01: openSession() sess1 failed" );

	res = openSession( &ctx, &sess2, &uuid );
	CHECK_RESULT( res, "test_01: openSession() sess2 failed" );
	
	res = closeSession( &sess1 );
	CHECK_RESULT( res, "test_01: closeSession() sess1 failed" );

	res = closeSession( &sess2 );
	CHECK_RESULT( res, "test_01: closeSession() sess2 failed" );
	
	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "test_01: freeSharedMem() failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "test_01: freeSharedMem() failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "test_01: finalizeContext() failed" );

	return res;

}

static void usage(void) {
	printf( "./test MODE\n"
			"MODE: FULL or REGISTER_KEYS or BENCHMARK or TEST_CAPSULES\n" );
}

int main(int argc, char *argv[]) {
	
	TEEC_Result res;

	if( (strcmp( argv[1], "BENCHMARK" ) == 0 && argc != 5) ) {
		usage();
		printf( "\tFor mode BENCHMARK: ./capsule_test BENCHMARK <num_iter> <capsule_path> <plaintext_path>\n\tBe sure to provide the full path for the capsule and plain text files.\n" );
		return 0;
	}

	if ( (strcmp( argv[1], "BENCHMARK" ) != 0 && argc != 2) ) {
		usage();
		return 0;
	}

	if( strcmp( argv[1], "FULL" ) != 0 && 
		strcmp( argv[1], "REGISTER_KEYS" ) != 0 &&
	    strcmp( argv[1], "BENCHMARK" ) != 0 &&
	 	strcmp( argv[1], "TEST_CAPSULES" ) != 0 &&
	 	strcmp( argv[1], "MEMORY" ) != 0 ) {
		usage();
		return 0;
	}

	if( strcmp( argv[1], "REGISTER_KEYS" ) == 0 ) {
		res = test_01();
		CHECK_RESULT( res, "test_01: failed" );
		PRINT_INFO( "test_01: passed\n" );
	
		res = test_02();
		CHECK_RESULT( res, "test_02: failed" );
		PRINT_INFO( "test_02: passed\n" );
	} else if( strcmp( argv[1], "FULL" ) == 0 ) {
		res = test_03();
		CHECK_RESULT( res, "test_03: failed" );
		PRINT_INFO( "test_03: passed\n" );

		res = test_04();
		CHECK_RESULT( res, "test_04: failed" );
		PRINT_INFO( "test_04: passed\n" );
		
		res = test_05();
		CHECK_RESULT( res, "test_05: failed" );
		PRINT_INFO( "test_05: passed\n" );

		res = test_06();
		CHECK_RESULT( res, "test_06: failed" );
		PRINT_INFO( "test_06: passed\n" );

		//res = test_07();
		//CHECK_RESULT( res, "test_07: failed" );
		//PRINT_INFO( "test_07: passed\n" );
	
		//res = test_08();
		//CHECK_RESULT( res, "test_08: failed" );
		//PRINT_INFO( "test_08: passed\n" );
		
		res = test_09();
		CHECK_RESULT( res, "test_09: failed" );
		PRINT_INFO( "test_09: passed\n" );		
	
		res = test_12();
		CHECK_RESULT( res, "test_12: failed" );
		PRINT_INFO( "test_12: passed\n" );
		
		res = test_13();
		CHECK_RESULT( res, "test_13: failed" );
		PRINT_INFO( "test_13: passed\n" );
	
	} else if( strcmp( argv[1], "TEST_CAPSULES" ) == 0 ) {
		
		res = test_10();
		CHECK_RESULT( res, "test_10: failed" );
		PRINT_INFO( "test_10: passed\n" );

	} else if( strcmp( argv[1], "BENCHMARK" ) == 0 ) {
		res = benchmark_capsule( argv[3], argv[4], atoi(argv[2] ) );
		CHECK_RESULT( res, "benchmark of %s vs. %s failed", argv[3], argv[4] );
		PRINT_INFO( "benchmark of %s vs. %s finished\n", argv[3], argv[4] );
	} else if( strcmp( argv[1], "MEMORY" ) == 0 ) {
		res = test_11();
		CHECK_RESULT( res, "memory test of failed");
		PRINT_INFO( "memory test finished \n");
	}
	return 0;
}
