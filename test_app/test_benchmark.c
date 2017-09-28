#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include "test_benchmark.h"
#include "test_helper.h"
#include "test_app.h"

/* Physical Counter Register */
static inline unsigned long long read_cntpct(void) {
	unsigned long long val;
#ifdef HIKEY
	asm volatile( "mrs %0, cntpct_el0" : "=r" (val) );
#else
	asm volatile( "mrrc p15, 0, %Q0, %R0, c14" : "=r" (val) );
#endif
	return val;
}

static inline unsigned int read_cntfrq(void) {
	unsigned int frq;
#ifdef HIKEY
	asm volatile( "mrs %0, cntfrq_el0" : "=r" (frq) );
#else
	asm volatile( "mrc p15, 0, %0, c14, c0, 0" : "=r" (frq) );
#endif
	return frq;
}

int test_benchmark( char* capsule, int n, int op ) {
	int 			   i = 0, sum = 0;
	int                fd, nr;
	char               buf[4096];
	unsigned long long cntpct_a, cntpct_b;
	unsigned int 	   cntfrq;

	cntfrq = read_cntfrq();
	printf( "CLEAR BENCHMARK FOR TEST...\n"
			"CNTFRQ: %u\n", cntfrq );

	/* OPEN */
	if( op == 0 ) {
		sum = 0;
		for( i = 0; i < n; i++ ) {
			cntpct_a = read_cntpct();
			fd = open_file( capsule, O_RDWR );
			cntpct_b = read_cntpct();
			if( fd < 0 ) {
				printf( "test_benchmark(): cannot open file %s\n", capsule );
				return -1;
			}	
			close( fd );
			sum += cntpct_b - cntpct_a;
		}
		printf( "OPEN: %f seconds \n", (float) sum / (float) cntfrq / (float) n );
	} else if( op == 1 ) {
		sum = 0;
		for( i = 0; i < n; i++ ) {
			fd = open_file( capsule, O_RDWR );
			if( fd < 0 ) {
				printf( "test_benchmark(): cannot open file %s\n", capsule );
				return -1;
			}	
			cntpct_a = read_cntpct();
			close( fd );
			cntpct_b = read_cntpct();
			sum += cntpct_b - cntpct_a;
		}
		printf( "CLOSE: %f seconds \n", (float) sum / (float) cntfrq / (float) n );

	} else if( op == 2 ) {
		fd = open_file( capsule, O_RDWR );
		/* LSEEK */
		sum = 0;
		for( i = 0; i < n; i++ ) {	
			cntpct_a = read_cntpct();
			int ns = lseek( fd, rand() % 1000000, SEEK_SET );
			cntpct_b = read_cntpct();
			sum += cntpct_b - cntpct_a;
		}
		printf( "LSEEK: %f seconds \n", (float) sum / (float) cntfrq / (float) n );
		close( fd );
	} else if( op == 3 ) {
		fd = open_file( capsule, O_RDWR );
		/* READ */
		sum = 0;
		for( i = 0; i < n; i++ ) {	
			int ns = lseek( fd, rand() % 1000000, SEEK_SET );
			cntpct_a = read_cntpct();
			nr = read( fd, buf, sizeof(buf) );
			cntpct_b = read_cntpct();
			sum += cntpct_b - cntpct_a;
		}
		printf( "READ: %f seconds \n", (float) sum / (float) cntfrq / (float) n );
		close( fd );
	} else if( op == 4 ) {
		fd = open_file( capsule, O_RDWR );
		/* WRITE */
		sum = 0;
		for( i = 0; i < n; i++ ) {	
			int ns = lseek( fd, rand() % 1000000, SEEK_SET );
			cntpct_a = read_cntpct();
			nr = write( fd, buf, sizeof(buf) );
			cntpct_b = read_cntpct();
			sum += cntpct_b - cntpct_a;
		}
		printf( "WRITE: %f seconds \n", (float) sum / (float) cntfrq / (float) n );
		close( fd );
	}

	return 0;
}
