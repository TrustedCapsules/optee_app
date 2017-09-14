#include <stdio.h>
#include <string.h>
#include <capsule.h>
#include "capsule_gen.h"
#include "capsule_util.h"

unsigned int   aes_key_len;
unsigned int   aes_iv_len;
unsigned int   aes_chunk_size;
unsigned char* aes_iv;
unsigned char* aes_key;
unsigned char* aes_id;

/* TODO: error checking on opening files, common error is no capsules dir, 
so the program seg faults. With error checking, this would be easier to spot */

/* Calls fread until either EOF or the buffer has been filled */
static int full_read( void *buf, size_t sz, size_t n, FILE* fp ) {
	int nr = 0;
	int len = 0;
	do {
		nr = fread( buf, sz, n, fp );
		len += nr;
	} while( nr > 0 && len < n );
	return len;
}

/* Call fwrite until all out the buffer has been written out */
static int full_write( void *buf, size_t sz, size_t n, FILE* fp ) {
	int nw = 0;
	int len = 0;
	do {
		nw = fwrite( buf, sz, n, fp );
		len += nw;
	} while( nw > 0 && len < n );
	return len;
}

/* Prints out the header of a capsule */
void strip_header( FILE* in, unsigned char* aes_key, 
				   struct TrustedCap *header ) {
	size_t 			  n;

	/* Skip the header */
	n = full_read( header, sizeof(char), sizeof( struct TrustedCap ), in );
	print_header( header, n, aes_key, aes_key_len, aes_iv, aes_iv_len );

}

/* Adds a header to a capsule and output a capsule */
void append_header( char *infile, char *outfile, 
					unsigned char* aes_key, unsigned char* aes_id ) {
	size_t 		      inlen;
	size_t            fsize = 0;
	unsigned char 	 *buffer = NULL;
	hash_state        md;
	unsigned char     hash[32];
	struct TrustedCap header;

	FILE *in = fopen( infile, "rb" );
	FILE *out = fopen( outfile, "wb" );
	FILE *content = fopen( "temp_capsule", "rb" );

	if( in == NULL || out == NULL || content == NULL ) {
		PRINT_INFO( "Append_header()-> unable to open files\n" );
		return;
	}

	buffer = (unsigned char*) malloc( aes_chunk_size );
	if( buffer == NULL ) {
		PRINT_INFO( "Append_header()-> malloc() failed\n" );
		return;
	}

	sha256_init( &md );

	/* Make space for header at beginning of file */
	fseek( out, sizeof( struct TrustedCap ), SEEK_SET );
	while( feof( content ) == 0 ) {
		inlen = full_read( hash, sizeof(char), sizeof(hash), content );
		sha256_process( &md, (const unsigned char*) hash, sizeof(hash) );
		fsize += inlen;
		full_write( hash, sizeof(char), sizeof(hash), out );
		
		inlen = full_read( buffer, sizeof(char), aes_chunk_size, content );
		fsize += inlen;
		full_write( buffer, sizeof(char), inlen, out );
	}

	sha256_done( &md, hash );

	/* Create and write header to file */
	fseek( out, 0, SEEK_SET );
	fill_header( &header, fsize, aes_key, aes_key_len, 
				  aes_iv, aes_iv_len, aes_id, hash, sizeof(hash) );
	full_write( &header, sizeof( struct TrustedCap ), 1, out );
	
	free( buffer );
	fclose( in );
	fclose( out );
	fclose( content );
	remove( "temp_capsule" );
}

/* Pre-processing step of combining the policy and data of a file */
void concatenate( char* datafile, char* policyfile, char* ptx,
			      char* datacopy, char* policycopy ) {
    FILE *data, *policy, *temp, *data_temp, *policy_temp;
	size_t nr,nw;
	char   buf[1024];

    data = fopen( datafile, "rb" );
    policy = fopen( policyfile, "rb" );

    temp = fopen( ptx, "wb" );
	data_temp = fopen( datacopy, "wb" );
    policy_temp = fopen( policycopy, "wb" );	

    char ch;
    while( ( ch = fgetc( policy ) ) != EOF ) {
	    fputc( ch, temp );
		fputc( ch, policy_temp );
	}

	fprintf( temp, DELIMITER );

	do {
		nr = full_read( buf, sizeof(char), sizeof(buf), data );
		nw = full_write( buf, sizeof(char), nr, data_temp ); 
		nw = full_write( buf, sizeof(char), nr, temp );
	} while ( nr >= sizeof(buf) );
	
	fclose( data_temp );
	fclose( policy_temp );
	fclose( data );
	fclose( policy );
	fclose( temp );
}

/* Encrypt a file. The buffer size controls the chunk size of an
 * encryption. Decryption must use the same chunk size 
 */
int encrypt_file( char* ptx ) {
	FILE 			*in, *out;
	unsigned char 	*buffer = NULL;
	size_t 			 inlen;
	unsigned char    hash[32];
	int				 i;

	in = fopen( ptx, "rb" );
	out = fopen( "temp_capsule", "wb" );
	if( in == NULL && out == NULL ) {
		PRINT_INFO( "Encrypt_file()-> unable to open file\n" );
		return -1;
	}

	buffer = (unsigned char*) malloc( aes_chunk_size );
	if( buffer == NULL ) {
		PRINT_INFO( "Encrypt_file()-> malloc() failed\n" );
	}

	while( feof( in ) == 0 ) {
		inlen = full_read( buffer, sizeof(char), aes_chunk_size, in );

		encrypt_content( buffer, inlen, hash, sizeof(hash), 
						 aes_key, aes_key_len, aes_iv, aes_iv_len, 
					     aes_chunk_size, 
						 inlen < aes_chunk_size ? true : false );

		full_write( hash, sizeof(char), sizeof(hash), out );
		full_write( buffer, sizeof(char), inlen, out );
	}
	
	free( buffer );
	fclose( out );
	fclose( in );

	return 0;
}

/* Prints out the decrypted file to stdout */
int decrypt_file( char *capsule ) {
	FILE 			 *in;
	unsigned char    *buffer;
	size_t 			  inlen, outlen;
	unsigned int      block = 0;
	
	unsigned char 	  delimiter[DELIMITER_SIZE] = DELIMITER;
	int 			  match_state = 0;
	bool 			  matched = false;
	int               start = 0, end = 0, saved = 0, i;
	
	struct TrustedCap header;
	hash_state        md;
	unsigned char     hash[32];

	in = fopen( capsule, "rb" );
	if( in == NULL ) {
		PRINT_INFO( "Decrypt_file()-> unable to open file\n" );
		return -1;
	}
	
	buffer = (unsigned char*) malloc( aes_chunk_size );
	if( buffer == NULL ) {
		PRINT_INFO( "Decrypt_file()-> malloc() failed\n" );
	}

	strip_header( in, aes_key, &header );
	
	sha256_init( &md );
	PRINT_INFO( "\nPolicy:\n" );

	while( feof(in) == 0 ) {
		block++;
		
		inlen = full_read( hash, sizeof(char), sizeof(hash), in );
	   	sha256_process( &md, (const unsigned char*) hash, sizeof( hash ) );	
		inlen = full_read( buffer, sizeof(char), aes_chunk_size, in );

		decrypt_content( buffer, inlen, hash, sizeof(hash), 
						 aes_key, aes_key_len, aes_iv, aes_iv_len, 
						 aes_chunk_size, 
						 inlen < aes_chunk_size ? true : false,
					  	 block );
		
		find_delimiter( buffer, inlen, &start, &end, &match_state, 
						&matched, delimiter, DELIMITER_SIZE );

		if( start >= 0 && saved > 0 ) {
			for( i = 0; i < saved; i++ ) {
				PRINT_INFO( "%c", delimiter[i] );
			}
			saved = 0;
		}

		if( matched == false ) {	
			if( start > 0 ) {
				saved = inlen - start;
				inlen = start;
			}
			for( i = 0; i < inlen; i++ ) {
				PRINT_INFO( "%c", buffer[i] );
			}
		} else {
			if( end > 0 && start > 0) {
				for( i = 0; i < start; i++ ) {
					PRINT_INFO( "%c", buffer[i] );
				}

				PRINT_INFO( "\nData:\n" );
			}

			for( i = end; i < inlen; i++ ) {
				PRINT_INFO( "%c", buffer[i] );
			}
		}

	}
	
	sha256_done( &md, hash );
	PRINT_INFO( "\n" );

	for( i = 0; i < sizeof(hash); i++ ) {
		if( hash[i] != header.hash[i] ) {
			PRINT_INFO( "Hash of chunk hashes do not match\n" );
			break;
		}
	}

	free( buffer );
	fclose( in );

	return 0;
}

static void usage( char *command ) {
	PRINT_INFO( "usage:      %s op keyfile infile outfile\n"
			    "op:         'encode' or 'decode'\n"
				"keyfile:    an RSA keyfile in .der format,\n"
				"            public for encode, private for decode\n"
				"datafile:   input data file to perform the op on\n"
				"policyfile: input policy file to perform the op on\n"
				"capsule:    output capsule file\n", command );
}

static void set_aes_key( char* keyname ) {
	set_capsule( keyname, &aes_key_len, &aes_key, &aes_iv_len,
				 &aes_iv, &aes_chunk_size, &aes_id );
}

int main( int argc, char *argv[] ) {
	if ( argc < 9 ) {
		usage( argv[0] );
	    return 0;
	}

    char *op = argv[1];
    char *keyname = argv[2];
    char *datafile = argv[3]; 
	char *policyfile = argv[4]; 
	char *capsule = argv[5];
	char *ptx = argv[6];
	char *datacopy = argv[7];
	char *policycopy = argv[8];

	set_aes_key( keyname );

	if( strcmp( op, "encode" ) == 0 ) {
        PRINT_INFO( "Concatenating %s with %s into %s\n", 
					datafile, policyfile, ptx );
	    concatenate( datafile, policyfile, ptx, datacopy, policycopy );

		PRINT_INFO( "Encrypting %s...\n", ptx );	  	
		encrypt_file( ptx );

		PRINT_INFO( "Copying contents from %s to %s and adding"
					" a trusted capsule header...\n", 
				    ptx, capsule );
	    append_header( ptx, capsule, aes_key, aes_id );
	} else if ( strcmp( op, "decode" ) == 0 ) {
		PRINT_INFO( "Decrypting %s\n", capsule );
	    decrypt_file( capsule );
	} else {
	    usage( argv[0] );
	    return 0;
	}
	
	return 0;
}

