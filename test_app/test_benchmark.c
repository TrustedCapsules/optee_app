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
	asm ( "mrs %0, cntpct_el0" : "=r" (val) );
#else
	asm volatile( "mrrc p15, 0, %Q0, %R0, c14" : "=r" (val) );
#endif
	return val;
}

static inline unsigned int read_cntfrq(void) {
	unsigned int frq;
#ifdef HIKEY
	asm ( "mrs %0, cntfrq_el0" : "=r" (frq) );
#else
	asm volatile( "mrc p15, 0, %0, c14, c0, 0" : "=r" (frq) );
#endif
	return frq;
}

/* Performance Counters */
static inline unsigned int perfcounter_getcycle(void) {
#ifdef HIKEY
	unsigned long long value;

	asm ( "mrs %0, PMCCNTR_EL0" : "=r" (value) );
#else
	unsigned int value;
	// Read CCNT Register
	asm volatile ("mrc p15, 0, %0, c9, c13, 0\t\n" : "=r"(value));
#endif
	return value;
}

static inline void perfcounter_init( int do_reset, int enable_divider  ) {
	// in general enable all counters (including cycle counter)
	int value = 1;

	if( do_reset ) {
		value |= 2;  //reset all counters to 0
		value |= 4;  //reset cycle counter to 0
	}

	if( enable_divider ) {
		value |= 8;  //reset "by 64" divider for CCNT
	}

	value |= 16;
#ifdef HIKEY
	asm ( "msr PMCR_EL0, %0" : : "r" (value) );

	asm ( "msr PMCNTENSET_EL0, %0" : : "r" (0x8000000f) );

	asm ( "msr PMOVSCLR_EL0, %0" : : "r" (0x8000000f) );
#else
	// porgram the performance counter control-register
	asm volatile ("mcr p15, 0, %0, c9, c12, 0\t\n" :: "r"(value));

	// enable all counters
	asm volatile ("mcr p15, 0, %0, c9, c12, 1\t\n" :: "r"(0x8000000f));

	// clear overflows
	asm volatile ("mcr p15, 0, %0, c9, c12, 3\t\n" :: "r"(0x8000000f));

#endif
}

int test_benchmark(void) {
	int 			   i = 0, sum = 0;
	int                fd, nr;
	char               buf[4096];
	char               capsule[] = "/etc/bio.capsule";
	unsigned long long cntpct_a, cntpct_b;
	unsigned int 	   cntfrq;

	cntfrq = read_cntfrq();
	printf( "cntfrq: %u\n", cntfrq );
	
	/* OPEN */
	sum = 0;
	for( i = 0; i < 10; i++ ) {
		cntpct_a = read_cntpct();
		fd = open_file( capsule, O_RDWR );
		cntpct_b = read_cntpct();
		CHECK_ERROR( fd, "test_benchmark(): cannot open file %s\n", capsule );	
		//nr = read_file( fd, 0, SEEK_SET, buf, sizeof(buf) );
		//nr = write_file( fd, 0, SEEK_SET, buf, sizeof(buf) );
		close( fd );

		sum += cntpct_b - cntpct_a;
	}
	printf( "OPEN: %f seconds \n", (float) sum / (float) cntfrq / 100.0 );
	
	/* READ */
/*
	sum = 0;
	fd = open_file( capsule, O_RDWR );
	CHECK_ERROR( fd, "test_benchmark(): cannot open file %s\n", capsule );	
	for( i = 0; i < 100; i++ ) {
		cntpct_a = read_cntpct();
		nr = read_file( fd, 0, SEEK_SET, buf, sizeof(buf) );
		cntpct_b = read_cntpct();

		sum += cntpct_b - cntpct_a;
	}

	close( fd );
	printf( "READ: %f seconds \n", (float) sum / (float) cntfrq / 100.0 );
*/	
	return 0;
}
