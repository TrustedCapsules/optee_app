#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <capsuleCommon.h>
#include <aes_keys.h>
#include <time.h>
#include <stdlib.h>
#include "err_ta.h"
#include "key_data.h"
#include "capsule_command.h"

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
	bool debug = false;
	int 			   i = 0;
	int                fd, nr, ns, nw;
	char               buf[4096];
	unsigned long long cntpct_a, cntpct_b;
	unsigned long long sum;
	unsigned int 	   cntfrq;

	cntfrq = read_cntfrq();
	printf( "CLEAR BENCHMARK FOR TEST...\n"
			"CNTFRQ: %u\n", cntfrq );

	/* OPEN */
	if( op == 0 ) {
		if (debug) {
			printf("[OPEN]: starting for loop with %s...\n", capsule);
		}
		sum = 0;
		for( i = 0; i < n; i++ ) {
			if (debug) {
				printf("\tRun %x\n", i);
				printf("\tMeasuring...\n");
			}
			cntpct_a = read_cntpct();
			fd = openat( AT_FDCWD, capsule, O_RDWR );
			cntpct_b = read_cntpct();
			if( fd < 0 ) {
				printf( "test_benchmark(): cannot open file %s\n", capsule );
				return -1;
			}
			if (debug) {
				printf("\tClosing file\n");
			}
			close( fd );
			sum = sum + cntpct_b - cntpct_a;
		}
		printf( "OPEN: %llu (%llu->%llu)\n", sum, cntpct_a, cntpct_b );
	} else if( op == 1 ) {
		if (debug) {
			printf("[CLOSE]: starting for loop with %s...\n", capsule);
		}
		sum = 0;
		for( i = 0; i < n; i++ ) {
			if (debug) {
				printf("\tRun %x\n", i);
				printf("\tOpening file\n");
			}
			fd = openat( AT_FDCWD, capsule, O_RDWR );
			if( fd < 0 ) {
				printf( "test_benchmark(): cannot open file %s\n", capsule );
				return -1;
			}	
			if (debug) {
				printf("\tMeasuring...\n");
			}
			cntpct_a = read_cntpct();
			close( fd );
			cntpct_b = read_cntpct();
			sum = sum + cntpct_b - cntpct_a;
		}
		printf( "CLOSE: %llu (%llu->%llu)\n", sum, cntpct_a, cntpct_b );

	} else if( op == 2 ) {
		if (debug) {
			printf("[LSEEK]: opening %s\n", capsule);
		}
		fd = openat( AT_FDCWD, capsule, O_RDWR );
		/* LSEEK */
		sum = 0;

		if (debug) {
			printf("[LSEEK]: starting for loop\n");
		}
		for( i = 0; i < n; i++ ) {	
			if (debug) {
				printf("\tMeasuring...\n");
			}
			cntpct_a = read_cntpct();
			ns = lseek( fd, rand() % 1000000, SEEK_SET );
			cntpct_b = read_cntpct();
			sum = sum + cntpct_b - cntpct_a;
		}
		printf( "LSEEK: %llu (%llu->%llu)\n", sum, cntpct_a, cntpct_b );
		if (debug) {
			printf("[LSEEK]: closing %s", capsule);
		}
		close( fd );
	} else if( op == 3 ) {
		if (debug) {
			printf("[READ]: opening %s\n", capsule);
		}
		fd = openat( AT_FDCWD, capsule, O_RDWR );
		/* READ */
		sum = 0;
		cntpct_a = 0;
		cntpct_b = 0;
		if (debug) {
			printf("[READ]: starting for loop\n");
		}
		for( i = 0; i < n; i++ ) {
			if (debug) {
				printf("\tSeeking to random offset...\n");
			}
			ns = lseek( fd, rand() % 1000000, SEEK_SET );
			if (debug) {
				printf("\tSeek returned %d\n", ns);
				printf("\tMeasuring...\n");
			}
			cntpct_a = read_cntpct();
			nr = read( fd, buf, sizeof(buf) );
			cntpct_b = read_cntpct();
			sum = sum + cntpct_b - cntpct_a;
		}
		printf( "READ: %llu (%llu->%llu)\n", sum, cntpct_a, cntpct_b );
		if (debug) {
			printf("[READ]: closing %s", capsule);
		}
		close( fd );
	} else if( op == 4 ) {
		if (debug) {
			printf("[WRITE]: opening %s\n", capsule);
		}
		fd = openat( AT_FDCWD, capsule, O_RDWR );
		/* WRITE */
		sum = 0;
		if (debug) {
			printf("[WRITE]: starting for loop\n");
		}
		for( i = 0; i < n; i++ ) {
			if (debug) {
				printf("\tSeeking to random offset...\n");
			}
			ns = lseek( fd, rand() % 1000000, SEEK_SET );
			if (debug) {
				printf("\tSeek returned %d\n", ns);
				printf("\tMeasuring...\n");
			}
			cntpct_a = read_cntpct();
			nw = write( fd, buf, sizeof(buf) );
			cntpct_b = read_cntpct();
			sum = sum + cntpct_b - cntpct_a;
		}
		printf( "WRITE: %llu (%llu->%llu)\n", sum, cntpct_a, cntpct_b );
		if (debug) {
			printf("[WRITE]: closing %s", capsule);
		}
		close( fd );
	}

	return 0;
}

void display_benchmark( int msqid ) {
	struct supp_buf buf;
	PRINT_INFO( "DISPLAY_BENCHMARK\n");
	buf.info.action = 1;
	msgsnd( msqid, &buf, sizeof( struct benchmarking_supp ), 0 );
	PRINT_INFO( "DISPLAYED\n" );
}

void clear_benchmark( int msqid ) {
	struct supp_buf buf;
	buf.info.action = 0;
	PRINT_INFO( "CLEAR_BENCHMARK\n");
	msgsnd( msqid, &buf, sizeof( struct benchmarking_supp ), 0 );

	PRINT_INFO( "CLEARED\n" );
}

void print_usage(bool bench) {
	if (bench){
		PRINT_INFO( "USAGE: ./capsule_breakdown BENCHMARK FILE [n] [op]\n"
			    "  n    number of iterations\n"
			    "  op   0 - open, 1 - close, 2 - lseek, 3 - read, 4 - write\n" );
	} else {
		PRINT_INFO( "USAGE: ./capsule_breakdown BENCHMARK | CLEAR | DISPLAY\n");
	}
}

int main(int argc, char *argv[]) {
/*
	TEEC_Result  res = TEEC_SUCCESS;
	TEEC_UUID    uuid = CAPSULE_UUID;
	TEEC_Context ctx;
	TEEC_Session sess;
*/
	int          msqid;
	key_t        key;

	/* set up msg queue to supplicant */
	if( (key = ftok( "/etc/other_capsules/bio.capsule", 'B' )) == -1 ) {
		printf( "msg queue error\n" );
		exit(1);
	}

	if( (msqid = msgget( key, 0666 | IPC_CREAT)) == -1 ) {
		printf( "msg queue get error\n" );
		exit(1);
	}

	if (argc < 1) {
		print_usage(false);
		goto out;
	}

	/* Initialize trusted capsule session */

	if( strcmp( argv[1], "CLEAR" ) == 0 ) {
		clear_benchmark( msqid );
	} else if( strcmp( argv[1], "BENCHMARK" ) == 0 ) {
		if (argc != 5) {
			PRINT_INFO("argc: %d\n", argc);
			print_usage(true);
			goto out;
		}
		test_benchmark( argv[2], atoi(argv[3]), atoi(argv[4]) );
	} else if( strcmp( argv[1], "DISPLAY" ) == 0 ) {
		display_benchmark( msqid );
	} else {
		print_usage(false);
	}

out:
	return 0;
}
