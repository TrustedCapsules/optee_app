#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <tomcrypt.h>

#include <capsuleCrypt.h>
#include <capsuleCommon.h>
#include <capsuleKeys.h>

#include "gen_helper.h"

void aesEncrypt( const unsigned char *ptx, unsigned char *ctx, size_t len,
				 capsuleEntry *e ) {
	process_ctr_aes( ptx, ctx, len, e->aesKey, e->aesKeyLength, 0, 
					 e->iv, e->ivLength, &ctr_encrypt );
}

void aesDecrypt( const unsigned char *ctx, unsigned char *ptx, size_t len,
				 capsuleEntry *e ) {
	process_ctr_aes( ctx, ptx, len, e->aesKey, e->aesKeyLength, 0, 
					 e->iv, e->ivLength, &ctr_decrypt );
}

bool getCapsuleKeys( char* capsuleName, capsuleEntry* c ) {

	size_t numCapsules = sizeof( capsule_data_array ) / sizeof( capsule_data );

    for( int i = 0; i < numCapsules; i++ ) {
        if( strcmp( capsuleName, capsule_data_array[i].name ) == 0 ) {
		// For now, we use the same key:iv pair for all capsules. 
    		memset( c->name, 0, sizeof( c->name ) );
		memset( c->id, 0, sizeof( c->id ) );
		memcpy( c->name, capsule_data_array[i].name, sizeof( capsule_data_array[i].name ) );
		memcpy( c->id, capsule_data_array[i].id, sizeof( capsule_data_array[i].id ) );
			
		c->aesKey = keyDefault;
		c->aesKeyLength = sizeof( keyDefault );
    		c->iv = ivDefault;
    		c->ivLength = sizeof( ivDefault );
            
		return true;
        }
    }
    
	return false;
}       

// fullRead calls fread until either EOF or the buffer has been filled
static int fullRead( void *buf, size_t sz, size_t n, FILE* fp ) {
    int nr = 0;
    int len = 0;
    do {
        nr = fread( buf, sz, n, fp );
        len += nr;
    } while( nr > 0 && len < n );
    return len * sz;
}

// fullWrite calls fwrite until all out the buffer has been written out
static int fullWrite( void *buf, size_t sz, size_t n, FILE* fp ) {
    int nw = 0;
    int len = 0;
    do {
        nw = fwrite( buf, sz, n, fp );
        len += nw;
    } while( nw > 0 && len < n );
    return len * sz;
}


// concatenateFiles perform the pre-processing step of combining the policy, 
// log, kvstore and data of a file
void concatenateFiles( char* datafile, char* policyfile, char* kvfile, char* ptx ) {
    FILE	*data, *policy, *kvstore, *plaintext; 
	char	 ch;
	data		= fopen( datafile, "rb" );
	policy		= fopen( policyfile, "rb" );
	kvstore		= fopen( kvfile, "rb" );

	plaintext	= fopen( ptx, "wb" );

    if( data == NULL ) {
        fprintf( stderr, "concatenateFiles(): unable to open %s\n", 
				datafile );
        return;
    }
    
    if( policy == NULL ) {
        fprintf( stderr, "concatenateFiles(): unable to open %s\n", 
				policyfile );
        return;
    }
    if( kvstore == NULL ) {
        fprintf( stderr, "concatenateFiles(): unable to open %s\n", 
				kvfile );
        return;
    }
    if( plaintext == NULL ) {
        fprintf( stderr, "concatenateFiles(): unable to open %s\n", 
				ptx );
        return;
    }
	// write delimiter -> plaintext file
    // fprintf( plaintext, DELIMITER );

    // read policy file -> plaintext file
    while( ( ch = fgetc( policy ) ) != EOF ) {
        fputc( ch, plaintext );
    }

    // write delimiter -> plaintext file
    fprintf( plaintext, DELIMITER );

    // read kvstore file -> plaintext file
    fseek( kvstore, 0L, SEEK_END );
    long kvLength = ftell( kvstore ) + 1;
    rewind( kvstore );
    char* kvString = (char*) malloc( kvLength * sizeof(char) );
    memset( kvString, 0, kvLength * sizeof( char ) );

    int     i = 0;
    while( ( ch = fgetc( kvstore ) ) != EOF ) {
		fputc( ch, plaintext );
		if( ch == '\n' ) {
			kvString[ i ] = ';';
		}
		kvString[ i ] = ch;
		i++;
    }

    // write delimiter -> plaintext file
    fprintf( plaintext, DELIMITER );

    // write log -> plaintext file
    time_t  clk = time(NULL);
    char*	timestamp = strtok( ctime( &clk ), "\n" );
    fprintf( plaintext, "%s - CREATED [ %s ]", timestamp,  kvString );

    // write delimiter -> plaintext file
    fprintf( plaintext, DELIMITER );

    // read data -> plaintext file
    char    buf[1024];
    size_t	nr;
	do {
        nr = fullRead( buf, sizeof(char), sizeof(buf), data );
        fullWrite( buf, sizeof(char), nr, plaintext );
    } while ( nr >= sizeof(buf) );
    
    // close files
    fclose( data );
    fclose( policy );
    fclose( kvstore );
    fclose( plaintext );
}

// encryptFile encrypts the plaintext file into an encrypted capsule
void encryptFile( capsuleEntry* e, char* ptxFile, char* ctxFile ) {
    unsigned char    hash[32];
    int              i;

    FILE *in	= fopen( ptxFile, "rb" );
    FILE *out	= fopen( ctxFile, "a" );
    if( in == NULL || out == NULL ) {
        fprintf( stderr, "encryptFile(): unable to open %s or %s\n", 
				ptxFile, ctxFile );
        return;
    }

    // get plaintext file size
    fseek( in, 0, SEEK_END );
    size_t ptxLength = ftell( in );
    fseek( in, 0, SEEK_SET );

    //printf("encryptFile(): plain text %zu B\n", ptxLength );

    // create buffer for file
    unsigned char* buffer = (unsigned char*) malloc( ptxLength );
    if( buffer == NULL ) {
        fprintf( stderr, "encryptFile(): malloc() failed\n" );
    	free( buffer );
    	fclose( out );
    	fclose( in );
    	return;    
    }

    // read in entire file
    if( fullRead( buffer, sizeof(char), ptxLength, in ) != ptxLength ) {
        fprintf( stderr,  "encryptFile(): fullRead() did not read %zu B\n", 
				ptxLength );
    	free( buffer );
    	fclose( out );
    	fclose( in );
    	return;    
    }

	// encrypt file
	aesEncrypt( buffer, buffer, ptxLength, e );

    // write file -> capsule
    fullWrite( buffer, sizeof(char), ptxLength, out );
    
    free( buffer );
    fclose( out );
    fclose( in );
}

// fillHeader constructs and encrypts trusted capsule header 
bool fillHeader( TrustedCap* header, size_t fsize, capsuleEntry *e, 
                 unsigned char* hash, size_t hashLen ) {

    if( hashLen != HASHLEN ) {
        fprintf( stderr, "fillHeader(): hash is wrong length\n" );
    	return false;
	}

    memset( header, 0, sizeof( TrustedCap ) );
    
    strcpy( header->pad, TRUSTEDCAP );
	aesEncrypt( e->id, header->aes_id, sizeof( header->aes_id ), e );
    header->capsize = (unsigned int) fsize;
    memcpy( header->hash, hash, hashLen );
	return true;
}


// writeHeader creates a capsule header from the plaintext file and writes it 
// to the capsule 
void writeHeader( capsuleEntry *e, const char *plaintext, const char *capsule ) {
    FILE *in 	= fopen( plaintext, "rb" );
    FILE *out 	= fopen( capsule, "wb" );

    if( in == NULL || out == NULL ) {
        printf( "writeHeader(): unable to open files %s or %s\n", 
				plaintext, capsule );
        return;
    }

    fseek(in, 0, SEEK_END);
    size_t ptxLength = ftell(in);
    fseek(in, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*) malloc( ptxLength * sizeof(char) );
    if( buffer == NULL ) {
        fprintf( stderr, "writeHeader(): malloc failed\n" );
        return;
    }
    
	// Read in everything after the header
    if( fullRead( buffer, sizeof(char), ptxLength, in ) != ptxLength ) {
        fprintf( stderr,  "writeHeader(): fullRead() did not read %zu B\n", 
				ptxLength );
    	free( buffer );
    	fclose( in );
    	fclose( out );
		return;
	}

    unsigned char	hash[HASHLEN];
	// Get hash data from plaintext
	hashData( buffer, ptxLength, hash, sizeof( hash ) );

    // Write header -> capsule
    TrustedCap 		header;
    fillHeader( &header, ptxLength, e, hash, sizeof(hash) );
    
	fseek( out, 0, SEEK_SET );
	if( fullWrite( &header, sizeof( TrustedCap ), 1, out ) != sizeof( TrustedCap ) ) {
		fprintf( stderr, "writeHeader(): fullWrite did not write %zu B\n", 
				 sizeof( TrustedCap ) );
	}
    
	free( buffer );
    fclose( in );
    fclose( out );
}

void encodeToCapsule( char* capsuleName, char* path, char* opath ) {
	// Generate full output path
	char oFullPathCapsule[255] = {0};
	memcpy( oFullPathCapsule, opath, strlen( opath ) );	
	strcat( oFullPathCapsule, capsuleName );
	strcat( oFullPathCapsule, ".capsule" );
	
	char oFullPathPlainText[255] = {0};
	memcpy( oFullPathPlainText, opath, strlen( opath ) );
	strcat( oFullPathPlainText, capsuleName );
	strcat( oFullPathPlainText, ".plaintext" );

	// Generate full input paths for data, kvstore, policy and log
	char 	dataFullPath[255] = {0};
	memcpy( dataFullPath, path, strlen( path ) );
	strcat( dataFullPath, capsuleName );
	strcat( dataFullPath, ".data" );
	
	char 	kvstoreFullPath[255] = {0};
	memcpy( kvstoreFullPath, path, strlen( path ) );
	strcat( kvstoreFullPath, capsuleName );
	strcat( kvstoreFullPath, ".kvstore" );
	
	char 	policyFullPath[255] = {0};
	memcpy( policyFullPath, path, strlen( path ) );
	strcat( policyFullPath, capsuleName );
	strcat( policyFullPath, ".policy" );
	
	//char	logFullPath[255] = {0};
	//memcpy( logFullPath, path, strlen( path ) );
	//strcat( logFullPath, capsuleName );
	//strcat( logFullPath, ".log" );
	
	capsuleEntry e;
	if( getCapsuleKeys( capsuleName, &e ) == false ) {
		fprintf( stderr, "encryptFile(): cannot find capsule keys %s\n", 
					capsuleName );
		return;
	}	

	//printf("\tConcatenating files...\n");
	// Concatenate input files into plaintext
	concatenateFiles( dataFullPath, policyFullPath, kvstoreFullPath, 
					oFullPathPlainText );

	//printf("\tWriting header...\n");
	// Write header	
	writeHeader( &e, oFullPathPlainText, oFullPathCapsule );	

	//printf("\tEncrypting capsule...\n");
	// Plaintext->Cipher text and write out to oFullPathCapsule
	encryptFile( &e, oFullPathPlainText, oFullPathCapsule );
}

// printHeader prints the trusted capsule header
void printHeader( TrustedCap* header, capsuleEntry* e ) {

    unsigned char id[4];
	aesDecrypt( header->aes_id, id, sizeof( id ), e );

    printf( "Header pad: %s\n", header->pad );
	printf( "Header capsule size: %u\n", header->capsize );
    printf( "Header id: " );
	for( int i = 0; i < sizeof( id ); i++ ) {
        printf( "%02x", id[i] );
    }
    printf( "\n" );

    printf( "Header Hash: " );
    for( int i = 0; i < sizeof( header->hash ); i++ ) {
        printf( "%02x", header->hash[i] );
    }
    printf( "\n" );
}

// stripHeader gets the header of a capsule, printing if allowed
void stripHeader( FILE* fp, TrustedCap *header, capsuleEntry *e, bool print ) {
    size_t n = fullRead( header, sizeof(char), sizeof( TrustedCap ), fp );
	if( print ) {
    	printHeader( header, e );
	}
}

// findDelim finds the location of the next 
void findDelim( unsigned char* buf, size_t blen, 
				int* dstart, int* dend, int* state, bool *matched, 
				unsigned char* delim, size_t dlen ) {
    int n = 0, m = 0, out_i = 0;

    if( *matched == true ) {
        *dstart = 0;
        *dend = 0;
        return;
    }

    for( n = 0; n < blen; n++ ) {
        if( *state == dlen ) {
            *matched = true;
            *state = 0;
                
            *dend = n;
            *dstart = n - dlen + 1; 

            break;
        }

        if( buf[n] == delim[*state] ) {
            ( *state )++;
        } else {
            if( buf[n] == delim[0] ) {
                *state = 1;
                *dstart = n;
            } else {
                *state = 0;
                *dstart = 0 ;
            }
        } 
    }
}

// parseSection finds the start:end of each section
void parseSection( unsigned char* buf, size_t len, range parts[4] ) {

    int last = 0, index = 0, start = 0, end = 0, match_state = 0;
    bool matched;
    unsigned char delimiter[DELIMITER_SIZE] = DELIMITER;

    do {
        matched = false;
        findDelim( buf+last, len - last, 
				   &start, &end, &match_state, 
				   &matched, delimiter, DELIMITER_SIZE );
        if (index < 4) {
            if (matched == true) {
                parts[index].start = last;
                parts[index].end = last + start;
                last += end;
                index++;
            } else {
                parts[index].start = last;
                parts[index].end = len;
                index++;
                break;
            }
        }
    } while( matched == true );
}

void printSection( unsigned char * buf, range parts[4], SECTION s ){
    bool print;
	for (int i = 0; i < 4; i++) {
        char* part;
        switch (i) {
            case 0:
                part = "Policy";
				print = s == ALL_SECTION || s == POLICY_SECTION;
                break;
            case 1:
                part = "KV Store";
				print = s == ALL_SECTION || s == KV_SECTION;
                break;
            case 2:
                part = "Log";
				print = s == ALL_SECTION || s == LOG_SECTION;
                break;
            case 3:
                part = "Data";
				print = s == ALL_SECTION || s == DATA_SECTION;
                break;
        }
		if( print ) {
        	printf("%s: %zu, %zu\n", part, parts[i].start, parts[i].end);
        	printf("%.*s\n\n", (int) ( parts[i].end - parts[i].start ), 
					buf + parts[i].start);
		}
    }
}


// decodeFromCapsule decrypts the capsule file to stdout
void decodeFromCapsule( char *capsuleName, char* path, SECTION s ) {
	// Generate full input path
	char fullPathCapsule[255] = {0};
	memcpy( fullPathCapsule, path, strlen( path ) );	
	strcat( fullPathCapsule, capsuleName );
	strcat( fullPathCapsule, ".capsule" );
	
	// Get capsule keys
	capsuleEntry e;
	if( getCapsuleKeys( capsuleName, &e ) == false ) {
		fprintf( stderr, "decodeFromCapsule(): cannot find capsule keys %s\n", 
					capsuleName );
		return;
	}	
   
	// Read capsule 
	FILE *fp = fopen( fullPathCapsule, "rb" );
    if( fp == NULL ) {
        fprintf( stderr, "decodeFromCapsule(): unable to open %s\n", 
				fullPathCapsule );
        return;
    }
    
    TrustedCap header;
    stripHeader( fp, &header, &e, s == HEADER_SECTION || s == ALL_SECTION );
	
	unsigned char* buffer = (unsigned char*) malloc( header.capsize * sizeof( char ) );
	if( buffer == NULL ) {
		fprintf( stderr, "decodeFromCapsule(): malloc failed\n" );
    	fclose( fp );
		return;
	}
    
    size_t r = fullRead( buffer, sizeof(char), header.capsize, fp );
	aesDecrypt( buffer, buffer, header.capsize, &e );
        
    range section[4];
    parseSection( buffer, header.capsize, section );
    printSection( buffer, section, s );

    free( buffer );
    fclose( fp );
    return;
}
