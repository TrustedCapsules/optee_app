#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <math.h>
#include <capsuleCommon.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "err_ta.h"
#include "capsule_command.h"

static uint64_t timespec_to_ns(struct timespec *ts)
{
	return ((uint64_t)ts->tv_sec * 1000000000) + ts->tv_nsec;
}

static uint64_t timespec_diff_ns(struct timespec *start, 
				                 struct timespec *end)
{
	return timespec_to_ns(end) - timespec_to_ns(start);
}

/* Benchmark open, read, write, lseek, close operations for a capsule */
TEEC_Result benchmark_capsule( char* capsule, char* ptx, int n ) {

	TEEC_Result     	res = TEEC_SUCCESS;
	TEEC_Context 		ctx;
	TEEC_Session 		sess;
	TEEC_UUID    		uuid = CAPSULE_UUID;
	int             	i, file, ns, nr, nw, fd = 10, pid = 12345;
    unsigned long long	diff, sum = 0, sum_sq = 0;
	struct timespec 	time1, time2;
	char                buffer[1024];

	TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
								 .flags = TEEC_MEM_INPUT, };
	TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
								  .flags = TEEC_MEM_OUTPUT, };


	PRINT_INFO( "Benchmarking capsule %s vs. %s\n", capsule, ptx );
	PRINT_INFO( "--------------------------------\n" );

	sum = 0;
	sum_sq = 0;

	/* Time the cost of open */	
	for( i = 0; i < n; i++ ) {
		clock_gettime( CLOCK_MONOTONIC, &time1 );
		file = open( ptx, O_RDWR );
		clock_gettime( CLOCK_MONOTONIC, &time2 );
   		if( file < 0 ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "benchmark_capsule: open() of ptx %s failed", 
					  ptx );
		}	
		close( file );
		diff = timespec_diff_ns( &time1, &time2 );
		sum += diff;
		sum_sq += diff*diff;
	}

	PRINT_INFO( "open: %llu ns (+/- %f ns) \n", 
				sum/n, sqrt( (double) (sum_sq/n - (sum*sum)/(n*n)) ) );

	file = open( ptx, O_RDWR );

	sum = 0;
	sum_sq = 0;

	/* Time the cost of lseek */
	for( i = 0; i < n; i++ ) {
		clock_gettime( CLOCK_MONOTONIC, &time1 );
		ns = lseek( file, rand(), SEEK_SET );
		clock_gettime( CLOCK_MONOTONIC, &time2 );
   		if( ns < 0 ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "benchmark_capsule: lseek() of ptx %s failed", 
					  ptx );
		}	
		diff = timespec_diff_ns( &time1, &time2 );
		sum += diff;
		sum_sq += diff*diff;
	}

	PRINT_INFO( "lseek: %llu ns (+/- %f ns) \n", 
				sum/n, sqrt( (double) (sum_sq/n - (sum*sum)/(n*n)) ) );
	
	sum = 0;
	sum_sq = 0;
	/* Time the cost of read */
	for( i = 0; i < n; i++ ) {
		ns = lseek( file, 0, SEEK_SET );
   		if( ns < 0 ) {
			CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT, "benchmark_capsule:"
						  " lseek() of ptx %s failed", ptx );
		}	
		clock_gettime( CLOCK_MONOTONIC, &time1 );
		nr = read( file, buffer, sizeof(buffer) );
		clock_gettime( CLOCK_MONOTONIC, &time2 );
   		if( nr < 0 ) {
			CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT, "benchmark_capsule:"
						  " read() of ptx %s failed", ptx );
		}	
		diff = timespec_diff_ns( &time1, &time2 );
		sum += diff;
		sum_sq += diff*diff;
	}

	PRINT_INFO( "read: %llu ns (+/- %f ns) \n", 
				sum/n, sqrt( (double) (sum_sq/n - (sum*sum)/(n*n)) ) );

	sum = 0;
	sum_sq = 0;
	/* Time the cost of write */
	for( i = 0; i < n; i++ ) {
		ns = lseek( file, 0, SEEK_SET );
   		if( ns < 0 ) {
			CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT, "benchmark_capsule:"
						  " lseek() of ptx %s failed", ptx );
		}	
		clock_gettime( CLOCK_MONOTONIC, &time1 );
		nw = write( file, buffer, sizeof(buffer) );
		clock_gettime( CLOCK_MONOTONIC, &time2 );
   		if( nw < 0 ) {
			CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT, "benchmark_capsule:"
						  " read() of ptx %s failed", ptx );
		}	
		diff = timespec_diff_ns( &time1, &time2 );
		sum += diff;
		sum_sq += diff*diff;
	}

	PRINT_INFO( "write: %llu ns (+/- %f ns) \n", 
				sum/n, sqrt( (double) (sum_sq/n - (sum*sum)/(n*n)) ) );
	
	close( file );	
	
	sum = 0;
	sum_sq = 0;
	/* Time the cost of close */	
	for( i = 0; i < n; i++ ) {
		file = open( ptx, O_RDWR );
   		if( file < 0 ) {
		CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
					  "benchmark_capsule: open() of ptx %s failed", 
					  ptx );
		}	
		clock_gettime( CLOCK_MONOTONIC, &time1 );
		close( file );
		clock_gettime( CLOCK_MONOTONIC, &time2 );
		diff = timespec_diff_ns( &time1, &time2 );
		sum += diff;
		sum_sq += diff*diff;
	}

	PRINT_INFO( "close: %llu ns (+/- %f ns) \n", 
				sum/n, sqrt( (double) (sum_sq/n - (sum*sum)/(n*n)) ) );
	
	/* ----------------------------------------------------------------------*/
	PRINT_INFO( "------------------------------\n" );
	
	res = initializeContext( &ctx ) ;
	CHECK_RESULT( res, "benchmark_capsule: initializeContext() failed" );

	
	res = allocateSharedMem( &ctx, &in_mem );
	CHECK_RESULT( res, "benchmark_capsule: allocateSharedMem() failed" );
	
	
	res = allocateSharedMem( &ctx, &out_mem );
	CHECK_RESULT( res, "benchmark_capsule: allocateSharedMem() failed" );

	/* Time the cost of openSession */
	sum = 0;
	sum_sq = 0;
	for( i = 0; i < n; i ++ ) {	
		clock_gettime( CLOCK_MONOTONIC, &time1 );
		res = openSession( &ctx, &sess, &uuid );
		clock_gettime( CLOCK_MONOTONIC, &time2 );
		CHECK_RESULT( res, "benchmark_capsule: openSession() failed" );
		res = closeSession( &sess );
		CHECK_RESULT( res, "benchmark_capsule: closeSession() failed" );
		diff = timespec_diff_ns( &time1, &time2 );
		sum += diff;
	   	sum_sq += diff*diff;	
	}
	PRINT_INFO( "openSession: %llu ns (+/- %f ns) \n", 
				sum/n, sqrt( (double) (sum_sq/n - (sum*sum)/(n*n)) ) );
	
	sum = 0;
	sum_sq = 0;
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "benchmark_capsule: openSession() failed" );

	/* Time the cost of capsule_open */
	for( i = 0; i < n; i++ ) {
		clock_gettime( CLOCK_MONOTONIC, &time1 );
		res = capsule_open( &sess, &in_mem, capsule, strlen(capsule), pid, fd );
		clock_gettime( CLOCK_MONOTONIC, &time2 );	
		CHECK_RESULT( res, "benchmark_capsule: capsule_open() of capsule %s failed",
							capsule );
		res = capsule_close( &sess, pid, fd );
		CHECK_RESULT( res, "benchmark_capsule: capsule_close() %s failed", 
					  capsule );
		diff = timespec_diff_ns( &time1, &time2 );
		sum += diff;
	   	sum_sq += diff*diff;	
	}
	
	res = closeSession( &sess );
	CHECK_RESULT( res, "benchmark_capsule: closeSession() failed" );

	PRINT_INFO( "capsule_open: %llu ns (+/- %f ns) \n", 
				sum/n, sqrt( (double) (sum_sq/n - (sum*sum)/(n*n)) ) );
	
	/* Time the cost of capsule_lseek */
	sum = 0;
	sum_sq = 0;
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "benchmark_capsule: openSession() failed" );
	res = capsule_open( &sess, &in_mem, capsule, strlen(capsule), pid, fd );
	CHECK_RESULT( res, "benchmark_capsule: capsule_open() of capsule %s failed",
						capsule );
	for( i = 0; i < n; i++ ) {
		clock_gettime( CLOCK_MONOTONIC, &time1 );
		res = capsule_lseek( &sess, rand(), START, (uint32_t*) &ns, pid, fd );
		clock_gettime( CLOCK_MONOTONIC, &time2 );	
		CHECK_RESULT( res, "benchmark_capsule: capsule_lseek() pos %u failed", ns );
		diff = timespec_diff_ns( &time1, &time2 );
		sum += diff;
	   	sum_sq += diff*diff;	
	}
	
	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "benchmark_capsule: capsule_close() %s failed", 
					   capsule );
	res = closeSession( &sess );
	CHECK_RESULT( res, "benchmark_capsule: closeSession() failed" );
	
	PRINT_INFO( "capsule_lseek: %llu ns (+/- %f ns) \n", 
				sum/n, sqrt( (double) (sum_sq/n - (sum*sum)/(n*n)) ) );
	
	/* Time the cost of capsule_read */
	sum = 0;
	sum_sq = 0;
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "benchmark_capsule: openSession() failed" );
	res = capsule_open( &sess, &in_mem, capsule, strlen(capsule), pid, fd );
	CHECK_RESULT( res, "benchmark_capsule: capsule_open() of capsule %s failed",
						capsule );
	
	for( i = 0; i < n; i++ ) {
		res = capsule_lseek( &sess, 0, START, (uint32_t*) &ns, pid, fd );
		CHECK_RESULT( res, "benchmark_capsule: capsule_lseek() pos %u failed", ns );
		clock_gettime( CLOCK_MONOTONIC, &time1 );
		res = capsule_read( &sess, &out_mem, buffer, sizeof(buffer), (uint32_t*) &nr, pid, fd );
		clock_gettime( CLOCK_MONOTONIC, &time2 );	
		CHECK_RESULT( res, "benchmark_capsule: capsule_read() failed" );
		diff = timespec_diff_ns( &time1, &time2 );
		sum += diff;
	   	sum_sq += diff*diff;	
	}
	
	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "benchmark_capsule: capsule_close() %s failed", 
					   capsule );
	res = closeSession( &sess );
	CHECK_RESULT( res, "benchmark_capsule: closeSession() failed" );
	
	PRINT_INFO( "capsule_read: %llu ns (+/- %f ns) \n", 
				sum/n, sqrt( (double) (sum_sq/n - (sum*sum)/(n*n)) ) );
	
	/* Time the cost of capsule_write */
	sum = 0;
	sum_sq = 0;
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "benchmark_capsule: openSession() failed" );
	res = capsule_open( &sess, &in_mem, capsule, strlen(capsule), pid, fd );
	CHECK_RESULT( res, "benchmark_capsule: capsule_open() of capsule %s failed",
						capsule );
	
	for( i = 0; i < n; i++ ) {
		res = capsule_lseek( &sess, 0, START, (uint32_t*) &ns, pid, fd );
		CHECK_RESULT( res, "benchmark_capsule: capsule_lseek() pos %u failed", ns );
		clock_gettime( CLOCK_MONOTONIC, &time1 );
		res = capsule_write( &sess, &in_mem, buffer, sizeof(buffer), (uint32_t*) &nw, pid, fd );
		clock_gettime( CLOCK_MONOTONIC, &time2 );	
		CHECK_RESULT( res, "benchmark_capsule: capsule_write() failed" );
		diff = timespec_diff_ns( &time1, &time2 );
		sum += diff;
	   	sum_sq += diff*diff;	
	}
	
	res = capsule_close( &sess, pid, fd );
	CHECK_RESULT( res, "benchmark_capsule: capsule_close() %s failed", 
					   capsule );
	res = closeSession( &sess );
	CHECK_RESULT( res, "benchmark_capsule: closeSession() failed" );
	
	PRINT_INFO( "capsule_write: %llu ns (+/- %f ns) \n", 
				sum/n, sqrt( (double) (sum_sq/n - (sum*sum)/(n*n)) ) );

	/* Time the cost of capsule_close */

	sum = 0;
	sum_sq = 0;
	
	res = openSession( &ctx, &sess, &uuid );
	CHECK_RESULT( res, "benchmark_capsule: openSession() failed" );
	
	for( i = 0; i < n; i++ ) {
		res = capsule_open( &sess, &in_mem, capsule, strlen(capsule), pid, fd );
		CHECK_RESULT( res, "benchmark_capsule: capsule_open() of capsule %s failed",
							capsule );
		clock_gettime( CLOCK_MONOTONIC, &time1 );
		res = capsule_close( &sess, pid, fd );
		clock_gettime( CLOCK_MONOTONIC, &time2 );	
		CHECK_RESULT( res, "benchmark_capsule: capsule_close() %s failed", 
					  capsule );
		diff = timespec_diff_ns( &time1, &time2 );
		sum += diff;
	   	sum_sq += diff*diff;	
	}
	
	res = closeSession( &sess );
	CHECK_RESULT( res, "benchmark_capsule: closeSession() failed" );
	
	PRINT_INFO( "capsule_close: %llu ns (+/- %f ns) \n", 
				sum/n, sqrt( (double) (sum_sq/n - (sum*sum)/(n*n)) ) );
	
	res = freeSharedMem( &in_mem );
	CHECK_RESULT( res, "benchmark_capsule: freeSharedMem() in_mem failed" );

	res = freeSharedMem( &out_mem );
	CHECK_RESULT( res, "benchmark_capsule: freeSharedMem() out_mem failed" );
	
	res = finalizeContext( &ctx );
	CHECK_RESULT( res, "benchmark_capsule: finalizeContext() failed" );

	return res;

}
