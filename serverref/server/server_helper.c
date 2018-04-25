#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fakekeys.h"
#include "hash.h"

capsuleTable* capsules = NULL;

size_t open_file( const char* filename, char *buf, size_t len ) {
	FILE    *fp;
	size_t   sz;
	
	fp = fopen( filename, "r+" );
	if( fp == NULL ) {
		printf( "Could not read file %s\n", filename );
		return 0;
	}

	fseek( fp, 0L, SEEK_END );
	sz = ftell( fp );
	if( sz > len ) {
		printf( "Buffer size too small, need %zu (B), got %zu (B)\n", sz, len );
		return 0;
	}

	memset( buf, 0, len );
	fseek( fp, 0L, SEEK_SET );
	sz = fread( buf, sizeof(char), sz, fp );

	fclose( fp );
	return sz;	
}

void registerCapsules(void){
	capsules = newCapsuleTable( 10 );
	
	int numCapsules = sizeof( capsuleManifestEntry ) / sizeof( struct manifest );
	for( int i = 0; i < numCapsules; i++ ) {
		char stateFile[255];
		char states[1024];
		strcat( stateFile, manifest[i].name );
		strcat( stateFile, ".state" );	

		size_t len = open_file( stateFile, states, sizeof(states ) );
	
		do {	
			char* valStart, valEnd;
			char* keyStart = states[ 0 ];
			char* keyEnd = strtok( states, ":" )
			if( keyEnd != NULL ) {
				valStart = keyEnd + 1;
				valEnd = strtok( valStart, "\n" );
			}
			
			if( keyEnd != NULL && valEnd != NULL ) {
				
			}	
		} while( keyEnd != NULL || valEnd != NULL );
	} 
}
