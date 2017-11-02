#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "test_app.h"
#include "test_helper.h"
#include <sched.h>
#include <math.h>

/* Runs tests on the bio capsule */
static char capsule_dir[] = "/etc";
static char data_write_throughput[] = "dummy.txt";


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
	asm ( "mrs %0, cntfrq_el0" : "=r" (frq) );
#else
	asm volatile( "mrc p15, 0, %0, c14, c0, 0" : "=r" (frq) );
#endif
	return frq;
}

static int get_size(int fd) {
	// Get file size
	int start_pos = lseek(fd, (size_t) 0, SEEK_CUR);
	int end = lseek(fd, (size_t) 0, SEEK_END);
	return end - start_pos;
}

/* This opens, writes, and closes a capsule. It is used by the load system function.
 * It writes a total of 10 KB. 
 */
static int open_write_close_capsule(char* name) {
	char		file_cap_abs[MAX_PATH];
	int			fd, nw, ns, whence, res;
	char		write_buf[10048]; // 10 KB
	char		ext[] = ".capsule";

	// Construct file name
	// TODO move to helper
	char full_name[strlen(name) + strlen(ext)+1];
	strcpy(full_name, name);
	strcat(full_name, ext);

	// Create capsule path
	abs_construct(file_cap_abs, capsule_dir, full_name);
	
	fd = open_file( file_cap_abs, O_RDWR);
	CHECK_EXIT( fd, "open_write_close_capsule(): parent pid %d cannot open"
					" abs path %s\n", getpid(), file_cap_abs );
	// Write 4 KB
	nw = 10048;
	// from start of file
	ns = 0;
	whence = SEEK_SET;

	nw = write_file( fd, ns, whence, write_buf, nw );

	res = close( fd );
	CHECK_EXIT( fd, "open_write_close_capsule(): parent pid %d cannot close"
					" abs path %s\n", getpid(), file_cap_abs );
	return res;
}

/* This opens, reads, and closes a capsule. It is used by the load system function.
 * It reads a total of 10 KB. 
 */
static int open_read_close_capsule(char* name) {
	char		file_cap_abs[MAX_PATH];
	int			fd, nr, ns, whence, res;
	char		read_buf[10000];
	char		ext[] = ".capsule";

	// Construct file name
	// TODO move to helper
	char full_name[strlen(name) + strlen(ext)+1];
	strcpy(full_name, name);
	strcat(full_name, ext);

	abs_construct(file_cap_abs, capsule_dir, full_name);
	
	fd = open_file( file_cap_abs, O_RDWR );
	
	CHECK_EXIT( fd, "open_read_close_capsule(): parent pid %d cannot open"
					" abs path %s\n", getpid(), file_cap_abs );

	nr = 10000;
	ns = 1;
	whence = SEEK_SET;

	int read = read_file( fd, ns, whence, read_buf, nr );

	res = close( fd );
	CHECK_EXIT( fd, "open_read_close_capsule(): parent pid %d cannot close"
					" abs path %s\n", getpid(), file_cap_abs );

	return res;
}

/*
 */
static void create_output_file_name(char* op, char* num_iter, char* file_path, char* num_bytes, char* output_file) {
	// Strip filename of path
	char* file_name = basename(file_path);
	// Replace '.' with '_'
	char file_name_copy[strlen(file_name)];
	strcpy(file_name_copy, file_name);
	int i;
	for (i = 0; i < strlen(file_name_copy); i++) {
		if(file_name_copy[i] == '.') {
			file_name_copy[i] = '_';
		}
	}

	strcpy(output_file, op);
	strcat(output_file, "_result_");
	strcat(output_file, file_name_copy);
	strcat(output_file, "_");
	strcat(output_file, num_iter);
	strcat(output_file, "_");
	strcat(output_file, num_bytes);
	strcat(output_file, ".txt");
}

/*
 */
static int open_capsule(char* capsule_name) {
	char	file_cap_abs[MAX_PATH];
	abs_construct( file_cap_abs, capsule_dir, capsule_name );

	int		fd = open_file( file_cap_abs, O_RDWR );
	CHECK_ERROR( fd, "open_capsule(): cannot open abs path %s\n",
					 file_cap_abs );
	return fd;
}

/*
 */
int test_read_throughput(char* file_name, int num_secs, int total_run_time) {
	printf("Testing read throughput on %s for %d seconds\n", file_name, num_secs);
	char		file_abs[MAX_PATH];
	int			fd, nr, ns, whence, res;
	long		read = 0;
	char		read_buf[4096];
	double 		throughput = -1;
	int 		count = 1;

	fd = open_file( file_name, O_RDWR );
	
	CHECK_EXIT( fd, "test_read_throughput(): cannot open"
					" abs path %s\n", file_name );

	nr = 4096;
	ns = 0;
	whence = SEEK_SET;

	srand((unsigned) time(NULL));

	clock_t last = clock(), start = clock();
	while (1) {
		clock_t current = clock();
		// read capsule
		read += read_file( fd, ns, whence, read_buf, nr );
		// record amount read
		last = current;

		// printf("Current: %d, Interval: %d\n", current, (start+num_secs*CLOCKS_PER_SEC*count));
		// printf("\tClocks per Sec: %d\n\tStart: %d\n\tInterval: %d\n\tCount: %d\n", CLOCKS_PER_SEC, start, num_secs, count);
		if (current >= (start + num_secs*CLOCKS_PER_SEC*count)) {
			throughput = (double) read / (double) num_secs;
			count++;
			read = 0;
		}

		// if we've reached a minute, we're done
		if (current >= (start + total_run_time*CLOCKS_PER_SEC)) {
			break;
		}
	}

	// double fsecs = (double) num_secs;
	// double fread = (double) read;
	// double throughput = fread / fsecs;

	printf("Read Throughput: %f\n", throughput);

	res = close( fd );
	CHECK_EXIT( fd, "test_read_throughput(): cannot close"
					" abs path %s\n", file_name );

	return 0;
}

/*
 */
int test_write_throughput(char* file_name, int num_secs, int total_run_time) {
	printf("Testing write throughput on %s for %d seconds\n", file_name, num_secs);
	char		file_abs[MAX_PATH];
	int			fd, nw, ns, whence, res;
	long		write_bytes = 0;
	char		write_buf[4096];
	double 		throughput = -1;
	int 		count = 1;

	fd = open_file( file_name, O_RDWR | O_CREAT );
	
	CHECK_EXIT( fd, "test_write_throughput(): cannot open"
					" abs path %s\n", file_name );

	int size = get_size(fd);

	nw = 4096;
	ns = 0;
	whence = SEEK_SET;

	clock_t last = clock(), start = clock();

	srand(time(NULL));

	while (1) {
		// Wrap lseek so it doesn't go past the end of the file. 
		ns = (rand() % size);
		clock_t current = clock();
		ns = lseek(fd, ns, whence);
		// read capsule
		write_bytes += write( fd, write_buf, nw );
		// record amount read
		last = current;

		if (current >= (start + num_secs*CLOCKS_PER_SEC*count)) {
			throughput = (double) write_bytes / (double) num_secs;
			count++;
			write_bytes = 0;
		}

		// if we've reached a minute, we're done
		if (current >= (start + total_run_time*CLOCKS_PER_SEC)) {
			break;
		}
	}
	// double fwrite = (double) write_bytes;
	// double fsecs = (double) num_secs;
	// double throughput = fwrite / fsecs;

	printf("Write Throughput: %f\n", throughput);

	res = close( fd );
	CHECK_EXIT( fd, "test_write_throughput(): cannot close"
					" abs path %s\n", file_name );

	return 0;
}

/* Have a process open 0, 1, 2, 3, 4 capsules and then measure the 
 * throughput difference for a write/read on something that isn't
 * a capsule. 
 */
int test_tainted_process(char* file_name, int num_capsules, int num_secs) {
	char*	capsules[] = {"test_1M_NULL_1KB.capsule", "test_1M_NULL_2KB.capsule", "test_1M_NULL_3KB.capsule", "test_1M_NULL_4KB.capsule"};
	int		i, k;
	int		file_descriptors[4];

	printf("Testing with %d capsules\n", num_capsules);

	// Open capsules (up to four)
	for (i = 0; i < num_capsules; i++) {
		printf("Opening %s\n", capsules[i]);
		int temp = open_capsule(capsules[i]);
		file_descriptors[i] = temp;
	}

	test_write_throughput(file_name, num_secs, num_secs*10);

	for (i = 0; i < num_capsules; i++) {
		printf("Closing %s\n", capsules[i]);
		int res = close(file_descriptors[i]);
		CHECK_EXIT( file_descriptors[i], "test_write_throughput(): cannot close"
					" abs path %s\n", capsules[i] );
	}

	return 0;
}

/* Launch a process on each core. They all read 10 KB and write 10 KB
 * to a null capsule. This is done every second. This "loads" the 
 * system so that every core is busy with a capsule. */
int load_system(void) {
	char*		capsules[8] = {"test_100KB_NULL_4KB.capsule",
							   "test_10KB_NULL_4KB.capsule", 
							   "test_10M_NULL_4KB.capsule", 
							   "test_1M_NULL_4KB.capsule",
							   "test_1M_NULL_1KB.capsule",
							   "test_1M_NULL_2KB.capsule",
							   "test_1M_NULL_3KB.capsule",
							   "test_1M_NULL_4KB.capsule"
							  };
	int 		ret = 0;
	int 		child_pid=0;
	int 		status;
	cpu_set_t 	my_set;
	int 		i;

	char* capsule_name = NULL;

	// Determine number of cores
	int numcores = sysconf(_SC_NPROCESSORS_ONLN);
	for (i = 0; i < numcores; i++) {
		CPU_ZERO(&my_set);
		CPU_SET(i, &my_set);
		// Spawn a process per core
		child_pid = fork();
		if ( child_pid < 0 ) {
			printf( "test_process_throughput(): error, unable to for %d process,"
					"ret %d\n", i, child_pid );
			if( i > 0 ) wait( &status );
			return -1;
		} else if( child_pid == 0 ) {
			capsule_name = capsules[i];
			// This is a child, break;
			break;
		} else {
			sched_setaffinity(child_pid, sizeof(cpu_set_t), &my_set);
		}
	}

	if( child_pid == 0 ) {
		// child
		srand((unsigned) time(NULL));

		clock_t last = clock(), start = clock();
		while (1) {
			clock_t current = clock();
			// Open, read, close every second
			if (current >= (last + 1*CLOCKS_PER_SEC)) {
				double val = ((double) rand())/(double) RAND_MAX;
				if (val > 0.5) {
					open_read_close_capsule(capsule_name);
				} else {
					open_write_close_capsule(capsule_name);
				}
				last = current;
			}

			sleep(1);
		}
	} 

	printf("System loaded\n");

	return ret;
}

// TODO Add option to choose which operation to test (so for a large file like 10M), 
// 		can test per operation inbetween reboots. 
int test_op_latency(char* file_name, int num_iter, int num_bytes, char* op) {
	printf("Testing latency for %s %d times, reading/writing %d bytes.\n", file_name, num_iter, num_bytes);
	int					fd, res, nr, nw, ns, whence, ns_res;
	int 				i, j, k;
	char				file_abs[MAX_PATH];
	char				buf[num_bytes];
	unsigned long long	cntpct_a, cntpct_b;
	unsigned int		cntfrq;
	char*				operations[5] = {"open", "read", "lseek", "write", "close"};
	FILE*				output_files[5];
	FILE*				output_file=NULL;
	int					run_all = 0;

	// Convert int parameters into strings to create output file names.
	char	num_iter_str[10];
	sprintf(num_iter_str, "%d", num_iter);

	char	num_bytes_str[10];
	sprintf(num_bytes_str, "%d", num_bytes);

	// Create output file names and file handles for all operations if no op is specified
    if (strcmp(op, "") == 0) {
		for (j = 0; j < 5; j++) {
			char output_file[1024 + strlen(file_name) + strlen(num_iter_str) + strlen(num_bytes_str)];
			create_output_file_name(operations[j], num_iter_str, file_name, num_bytes_str, output_file);
			printf("Output file [%s] created.\n", output_file);
			output_files[j] = fopen(output_file, "w");
		}
		run_all = 1;
    } else {
		char temp[1024 + strlen(file_name) + strlen(num_iter_str) + strlen(num_bytes_str)];
		create_output_file_name(op, num_iter_str, file_name, num_bytes_str, temp);
		printf("Output file [%s] created.\n", temp);
		output_file = fopen(temp, "w");
	}

	// Get count frequency
	cntfrq = read_cntfrq();

	// Construct the file path (assume everything is in the capsule dir)
	// abs_construct( file_abs, capsule_dir, file_name );

	srand((unsigned) time(NULL));

	if (strcmp(op, "open") == 0 || run_all != 0) {
		// Iterate for specific value
		for (i = 0; i < num_iter; i++) {
			// printf("Opening file, count: %d\n", i);
			// ------------ TIME OPEN ------------
			cntpct_a = read_cntpct();
			fd = open_file( file_name, O_RDWR );
			cntpct_b = read_cntpct();
			CHECK_ERROR( fd, "test_op_latency(): cannot open abs path %s\n",
						 file_name );
			if (run_all != 0) {
				fprintf(output_files[0], "read_cntpct: %llu cycles, cntfrq: %u\n", cntpct_b - cntpct_a, cntfrq);
				fflush( output_files[0] );
			} else {
				fprintf(output_file, "read_cntpct: %llu cycles, cntfrq: %u\n", cntpct_b - cntpct_a, cntfrq);
				fflush( output_file );
			}
			// ------------ DONE OPEN ------------
			nr = close( fd );
			CHECK_EXIT( nr, "test_op_latency(): cannot close"
					" abs path %s\n", file_name );
		}
	}

	printf("Opening %s\n", file_name);
	// Open file for lseek, read, write
	fd = open_file( file_name, O_RDWR );
	CHECK_ERROR( fd, "test_op_latency(): cannot open abs path %s\n", file_name);

	if (strcmp(op, "lseek") == 0 || run_all != 0) {
		for (i = 0; i < num_iter; i++) {
			// ------------ PREP LSEEK -----------
			// Set seek parameters (random)
			int size = get_size(fd);
			ns = (rand() % (size));
			// printf("Seeking to: %d\n", ns);
			whence = SEEK_SET;

			// ------------ TIME LSEEK ------------
			cntpct_a = read_cntpct();
			ns_res = lseek(fd, ns, whence);
			cntpct_b = read_cntpct();
			if( ns_res < 0 ) {
				printf( "lseek error! ns: %d\n", ns_res);
				return -1;
			}

			if (run_all != 0) {
				fprintf(output_files[2], "read_cntpct: %llu cycles, cntfrq: %u\n", cntpct_b - cntpct_a, cntfrq);
				fflush( output_files[2] );
			} else {
				fprintf(output_file, "read_cntpct: %llu cycles, cntfrq: %u\n", cntpct_b - cntpct_a, cntfrq);
				fflush( output_file );
			}
			// ------------ DONE LSEEK -----------
		}
	}

	if (strcmp(op, "read") == 0 || run_all != 0) {
		for (i = 0; i < num_iter; i++) {
			// ------------ PREP READ ------------
			nr = num_bytes;
			// Random seek position
			int size = get_size(fd);
			ns = (rand() % (size));
			whence = SEEK_SET;
			ns_res = lseek(fd, ns, whence);
			if( ns_res < 0) {
				printf( "lseek error! ns: %d\n", ns_res);
				return -1;
			}

			// ------------ TIME READ ------------
			cntpct_a = read_cntpct();
			nr = read( fd, buf, nr );
			cntpct_b = read_cntpct();
			if( nr < 0 ) {
				printf( "read error! nr: %d\n", nr);
				return -1;
			}
			if (run_all != 0) {
				fprintf(output_files[1], "read_cntpct: %llu cycles, cntfrq: %u\n", cntpct_b - cntpct_a, cntfrq);
				fflush( output_files[1] );
			} else {
				fprintf(output_file, "read_cntpct: %llu cycles, cntfrq: %u\n", cntpct_b - cntpct_a, cntfrq);
				fflush( output_file );
			}
		}
	}

	if (strcmp(op, "write") == 0 || run_all != 0) {
		for (i = 0; i < num_iter; i++) {
			nw = num_bytes;
			// ------------ PREP WRITE ------------
			// lseek to random
			int size = get_size(fd);
			ns = (rand() %(size));
			ns_res = lseek(fd, ns, whence);
			if( ns_res < 0 ){
				printf("lseek error! ns: %d\n", ns_res);
				return -1;
			}

			// ------------ TIME WRITE ------------
			cntpct_a = read_cntpct();
			nw = write( fd, buf, nw );
			cntpct_b = read_cntpct();
			if( nw < 0 ) {
				printf( "write error! nw: %d\n", nw);
				return -1;
			}
			if (run_all != 0) {
				fprintf(output_files[3], "read_cntpct: %llu cycles, cntfrq: %u\n", cntpct_b - cntpct_a, cntfrq);
				fflush( output_files[3] );
			} else {
				fprintf(output_file, "read_cntpct: %llu cycles, cntfrq: %u\n", cntpct_b - cntpct_a, cntfrq);
				fflush( output_file );
			}
			// ----------- DONE WRITE -------------
		}
	}

	// Close the file
	printf("Closing %s\n", file_name);
	nr = close( fd );
	CHECK_EXIT( fd, "test_op_latency(): cannot close"
				" abs path %s\n", file_name );

	if (strcmp(op, "close") == 0 || run_all != 0) {
		for (i = 0; i < num_iter; i++) {
			fd = open_file( file_name, O_RDWR );
			CHECK_ERROR( fd, "test_op_latency(): cannot open abs path %s\n", file_name)
			// ------------ TIME CLOSE ------------
			cntpct_a = read_cntpct();
			nr = close( fd );
			cntpct_b = read_cntpct();
			if (run_all != 0) {
				fprintf(output_files[4], "read_cntpct: %llu cycles, cntfrq: %u\n", cntpct_b - cntpct_a, cntfrq);
				fflush( output_files[4] );
			} else {
				fprintf(output_file, "read_cntpct: %llu cycles, cntfrq: %u\n", cntpct_b - cntpct_a, cntfrq);
				fflush( output_file );
			}
			CHECK_EXIT( nr, "test_op_latency(): cannot close"
					" abs path %s\n", file_name );
			// ----------- DONE CLOSE ------------
		}
	}

	if (run_all != 0) {
		for( k = 0; k < 5; k++) {
			fclose( output_files[k] );
		}
	} else {
		fclose( output_file );
	}

	return 0;
}
