#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "test_bio.h"
#include "test_short_story.h"
#include "test_benchmark.h"
#include "test_performance.h"

void usage(void) {
	printf( "Usage: test_app MODE CAPSULE MODE_ARGS\n"
		    "   -MODE     	single, multi, benchmark\n"
		    "   -CAPSULE  	bio, short_story\n"
			"	-MODE_ARGS	depends on mode\n");
}

int main( int argc, char** argv ) {

	if( argc < 2 || argc > 6 ) {
		usage();
		return 0;
	}

	if( strcmp( argv[1], "single" ) == 0 ) {
		if( strcmp( argv[2], "bio" ) == 0 ) {
			test_bio_single();
		} else if( strcmp( argv[2], "short_story" ) == 0 ) {
			test_short_story_single();
		} else {
			usage();
		}
	} else if( strcmp( argv[1], "multi" ) == 0 ) {
		if( strcmp( argv[2], "bio" ) == 0 ) {
			test_bio_multi();	
		} else if( strcmp( argv[2], "short_story" ) == 0 ) {
			test_short_story_multi();
		} else {
			usage();
		}
	} else if( strcmp( argv[1], "benchmark" ) == 0 ) {
		test_benchmark( argv[2], atoi(argv[3]), atoi(argv[4]) );
	} else if( strcmp( argv[1], "load_system" ) == 0 ) {
		// file name
		load_system();
	} else if( strcmp( argv[1], "test_throughput" ) == 0 ) {
		if (argc != 5) {
			printf("MODE_ARGS: <file_name> <seconds_interval> <total_seconds>\n");
			usage();
			return 0;
		}
		// file name, number of seconds
		test_read_throughput(argv[2], strtol(argv[3], (char **) NULL, 10), strtol(argv[4], (char **) NULL, 10));
		test_write_throughput(argv[2], strtol(argv[3], (char **) NULL, 10), strtol(argv[4], (char **) NULL, 10));
	} else if (strcmp( argv[1], "tainted_process") == 0)  {
		if (argc != 5) {
			printf("MODE_ARGS: <file_name> <number_of_capsules> <number_of_seconds>\n");
			usage();
			return 0;
		}
		// file name, number of capsules, number of seconds
		test_tainted_process(argv[2], strtol(argv[3], (char**) NULL, 10), strtol(argv[4], (char**) NULL, 10));
	} else if (strcmp( argv[1], "test_latency" ) == 0 ) {
		char* op;
		if (argc == 5 ) {
			op = "";
		} else if (argc == 6) {
			op = argv[5];
		} else {
			printf("MODE_ARGS: <file_name> <number_of_iterations> <number_of_bytes> <operation>\n");
			usage();
			return 0;
		}
		printf("Operation: %s\n", op);
		// File name, iterations, bytes
		test_op_latency(argv[2], strtol(argv[3], (char **) NULL, 10), strtol(argv[4], (char **) NULL, 10), op);
	} else {
		printf("Unknown command: %s\n", argv[1]);
		usage();
	}
	
	
	return 0;
}
