#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "gen_helper.h"

static void usage() {
    printf( "Usage: cgen <op> -n <capsule_name> [-p path] [-o outpath] [-s SECTION]\n\n"
            "  Expected structure with -n NAME:\n"
            "  path flag must contain folder NAME\n"
            "  and contain NAME.kvstore, NAME.data, NAME.policy\n\n"
			"  encode	encodes a plaintext policy, data, log, kvstore into capsule\n"
			"\t-n   	capsule name [Required]\n"
			"\t-u   	capsule uuid [Default: ffffffffffffffffffffffffffffffff]\n"
			"\t-p   	path [Default: ./]\n"
			"\t-o   	output path [Default: ./]\n"
			"  decode	decodes capsule into plaintext policy, data, log, kvstore\n"
			"\t-n   	capsule name [Required]\n"
			"\t-p   	path [Default: ./]\n"
			"\t-s   	section to decode [Default: all] [Options: header, policy, kvstore, log, data]\n\n"
		  );
}

int main( int argc, char *argv[] ) {
    int     opt, optid = 1;
    char    message[80] = "";

	if( argc < 2 ) {
		usage();
		return 0;
	}

	char*	op = argv[1];
    char   *optparse;
    if (strcmp(op, "encode") == 0) {
        optparse = "n:u:p:o:";
    } else if (strcmp(op, "decode") == 0) {
        optparse = "n:p:s:";
    } else {
		usage();
    	return 0;
	}
           
	char *capsuleName = NULL;
	char *path = "./"; 
	char *opath = "./";
	char *uuid = "ffffffffffffffffffffffffffffffff";
	char *section = "all";
	SECTION t = ALL_SECTION;

	while ((opt = getopt(argc, argv, optparse)) != -1) {
		switch (opt) {
		case 'n':
			capsuleName = optarg;
			break;
		case 'u':
			uuid = optarg;
			break;
        case 'p':
			path = optarg;
			break;
		case 'o':
			opath = optarg;
			break;
		case 's':
			section = optarg;
			if( strcmp( section, "header" ) == 0 ) {
				t = HEADER_SECTION;
			} else if( strcmp( section, "policy" ) == 0 ) {
				t = POLICY_SECTION;
			} else if( strcmp( section, "kvstore" ) == 0 ) {
				t = KV_SECTION;
			} else if( strcmp( section, "log" ) == 0 ) {
				t = LOG_SECTION;
			} else if( strcmp( section, "data" ) == 0 ) {
				t = DATA_SECTION;
			} else {
				t = ALL_SECTION;
			}
			break;
		default:
			usage();
			return 0;
		}
	}

    if ( capsuleName == NULL ) {
        usage();
        return 1;
    }

    if( strcmp( op, "encode" ) == 0 ) {
		encodeToCapsule( capsuleName, path, opath, uuid );
    } else if ( strcmp( op, "decode" ) == 0 ) {
        decodeFromCapsule( capsuleName, path, t );
    }

    return 0;
}

