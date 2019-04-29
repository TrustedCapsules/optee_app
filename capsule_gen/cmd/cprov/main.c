#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <tee_client_api.h>
#include "register_capsule.h"
#include "err_ta.h"

static void usage() {
    printf( "\ncprov -n <capsule name> [-p path]\n"
			"\n Utility to register capsule keys and state files in secure storage."
			"\n\t-n 	capsule name\n"
			"\n\t-p   	path, defaults to pwd\n"
		  );
}

int main( int argc, char *argv[] ) {
    int     opt, optid = 1;
    char   *optparse = "n:p:";
    TEEC_Result res = TEEC_SUCCESS;

	if( argc < 2 ) {
		usage();
		return 0;
	} 
      
	char *capsuleName = NULL;
	char *path = "./"; 
		
	while ((opt = getopt(argc, argv, optparse)) != -1) {
		switch (opt) {
		case 'n':
			capsuleName = optarg;
			break;
		case 'p':
			path = optarg;
			break;
		default:
			usage();
			return 0;
		}
	}

    if ( capsuleName == NULL ) {
        usage();
        return 0;
    }

    
    res = registerCapsule( capsuleName, path);
	CHECK_RESULT(res, "register_capsule failed");
	return 0;
}

