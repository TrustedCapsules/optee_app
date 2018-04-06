#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <capsule.h>
#include <time.h>
#include "capsule_gen.h"
#include "capsule_util.h"

unsigned int   aes_key_len;
unsigned int   aes_iv_len;
//unsigned int   aes_chunk_size;
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
    size_t            n;

    /* Skip the header */
    n = full_read( header, sizeof(char), sizeof( struct TrustedCap ), in );
    print_header( header, n, aes_key, aes_key_len, aes_iv, aes_iv_len );

}

/* Adds a header to a capsule and output a capsule */
void append_header( char *infile, char *outfile, 
                    unsigned char* aes_key, unsigned char* aes_id ) {
    size_t            inlen, insize;
    size_t            fsize = 0;
    unsigned char    *buffer = NULL;
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

    fseek(in, 0, SEEK_END);
    insize = ftell(in);
    fseek(in, 0, SEEK_SET);

    buffer = (unsigned char*) malloc( insize );
    if( buffer == NULL ) {
        PRINT_INFO( "Append_header()-> malloc(%lu) failed\n", insize );
        return;
    }

    sha256_init( &md );

    /* Make space for header at beginning of file */
    fseek( out, sizeof( struct TrustedCap ), SEEK_SET );
    
    // Read in everything after the header
    inlen = full_read( buffer, sizeof(char), insize, content );
    // Hash what you read
    sha256_process( &md, (const unsigned char*) buffer, insize );

    // Finish hash operation
    sha256_done( &md, hash );

    fsize += inlen;
    // Write the buffer to the output file
    full_write( buffer, sizeof(char), inlen, out );

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
void concatenate( char* datafile, char* policyfile, char* kvfile, char* ptx,
                  char* datacopy, char* policycopy, char* kvstorecopy, char* logcopy,
                  char* keyname ) {
    FILE   *data, 
           *policy, 
           *kvstore, 
           *temp, 
           *data_temp, 
           *policy_temp, 
           *kv_temp,
           *log_temp;
    size_t  nr,nw;
    char    buf[1024];
    char   *kv_string;
    int     i = 0;
    long    kv_len;
    char    ch;
    time_t  clk = time(NULL);
    char*   timestamp = strtok(ctime(&clk), "\n");;

    data = fopen( datafile, "rb" );
    policy = fopen( policyfile, "rb" );
    kvstore = fopen( kvfile, "rb" );

    // Get kv_len
    fseek(kvstore, 0L, SEEK_END);
    kv_len = ftell(kvstore) + 1;
    rewind(kvstore);
    kv_string = malloc(kv_len*sizeof(char));

    temp = fopen( ptx, "wb" );
    data_temp = fopen( datacopy, "wb" );
    policy_temp = fopen( policycopy, "wb" );
    kv_temp = fopen( kvstorecopy, "wb" );
    log_temp = fopen( logcopy, "wb" );

    // Read in policy file and write it to the temp file
    while( ( ch = fgetc( policy ) ) != EOF ) {
        fputc( ch, temp );
        fputc( ch, policy_temp );
    }

    // Write delimiter
    fprintf( temp, DELIMITER );

    // Write default KV store
    while( ( ch = fgetc( kvstore ) ) != EOF ) {
        if (ch == '\n') {
            fputc( ';', temp );
            fputc( ';', kv_temp );
            kv_string[i] = ';';
        } else {
            fputc( ch, temp );
            fputc( ch, kv_temp );
            kv_string[i] = ch;
        }
        i++;
    }

    kv_string[kv_len - 1] = '\0'; // Make kv string null terminated

    parse_kvstore( (unsigned char*) kv_string, kv_len );

    // Write delimiter
    fprintf( temp, DELIMITER );

    // Write default log
    fprintf( temp, "%s - CREATED %s [ %s ]", timestamp, keyname, kv_string );
    fprintf( log_temp, "%s - CREATED %s [ %s ]", timestamp, keyname, kv_string );

    // Write delimiter
    fprintf( temp, DELIMITER );

    // Read in data and write to temp file
    do {
        nr = full_read( buf, sizeof(char), sizeof(buf), data );
        nw = full_write( buf, sizeof(char), nr, data_temp ); 
        nw = full_write( buf, sizeof(char), nr, temp );
    } while ( nr >= sizeof(buf) );
    
    // Close given files
    fclose( data );
    fclose( policy );
    fclose( kvstore );

    // Close temp files
    fclose( temp );
    fclose( data_temp );
    fclose( policy_temp );
    fclose( kv_temp );
    fclose( log_temp );

    // Free kv string
    free(kv_string);
}

/* Encrypt a file. The buffer size controls the chunk size of an
 * encryption. Decryption must use the same chunk size 
 */
int encrypt_file( char* ptx ) {
    FILE            *in, *out;
    unsigned char   *buffer = NULL;
    size_t           inlen, insize;
    unsigned char    hash[32];
    int              i;

    in = fopen( ptx, "rb" );
    out = fopen( "temp_capsule", "wb" );
    if( in == NULL && out == NULL ) {
        PRINT_INFO( "Encrypt_file()-> unable to open file\n" );
        return -1;
    }

    // Get file size
    fseek(in, 0, SEEK_END);
    insize = ftell(in);
    fseek(in, 0, SEEK_SET);

    PRINT_INFO("Plain text size: %lu\n", insize);

    // Create buffer for file
    buffer = (unsigned char*) malloc( insize );
    if( buffer == NULL ) {
        PRINT_INFO( "Encrypt_file()-> malloc() failed\n" );
        goto exit;
    }

    // Read in entire file
    inlen = full_read( buffer, sizeof(char), insize, in );

    // Check to see if the data read is equal to the file size
    if (inlen != insize) {
        PRINT_INFO( "Encrypt_file()-> full_read() read %lu != file size %lu\n", 
                    inlen, insize);
        goto exit;
    }

    // Encrypt the entire file and hash it
    encrypt_content( buffer, inlen, //hash, sizeof(hash), 
                     aes_key, aes_key_len, aes_iv, aes_iv_len );

    // Write the hash
    // full_write( hash, sizeof(char), sizeof(hash), out );
    // Write the file
    full_write( buffer, sizeof(char), inlen, out );
    
    fseek(out, 0, SEEK_END);
    size_t outsize = ftell(out);
    fseek(out, 0, SEEK_SET);

    PRINT_INFO("Encrypted data size: %lu\n", outsize);
exit:
    free( buffer );
    fclose( out );
    fclose( in );

    return 0;
}

/* Prints out the decrypted file to stdout */
int decrypt_file( char *capsule ) {
    FILE             *in;
    unsigned char    *buffer;
    size_t            inlen, outlen, contentsize;
    unsigned int      block = 0;
    
    unsigned char     delimiter[DELIMITER_SIZE] = DELIMITER;
    int               match_state = 0;
    bool              matched = false;
    int               start = 0, end = 0, saved = 0, i;
    
    struct TrustedCap header;
    hash_state        md;
    unsigned char     hash[32];

    in = fopen( capsule, "rb" );
    if( in == NULL ) {
        PRINT_INFO( "Decrypt_file()-> unable to open file [%s]\n", capsule );
        return -1;
    }
    
    // TODO: remove hash of hash in header? --> get fsize from header
    strip_header( in, aes_key, &header );
    contentsize = header.capsize;
    PRINT_INFO( "File size (according to header): %u\n", header.capsize);
    
    buffer = (unsigned char*) malloc( contentsize );
    if( buffer == NULL ) {
        PRINT_INFO( "Decrypt_file()-> malloc(%lu) failed\n", contentsize );
        goto exit;
    }

    // sha256_init( &md );

    // inlen = full_read( hash, sizeof(char), sizeof(hash), in );
    // sha256_process( &md, (const unsigned char*) hash, sizeof( hash ) ); 
    inlen = full_read( buffer, sizeof(char), contentsize, in );

    decrypt_content( buffer, inlen, //hash, sizeof(hash), 
                     aes_key, aes_key_len, aes_iv, aes_iv_len);
        
    struct range parts[4];

    populate_parts( buffer, inlen, parts );

    // printf("[capsule_gen] Ranges:\n");
    print_parts( buffer, parts );

    // sha256_done( &md, hash );

    // for( i = 0; i < sizeof(hash); i++ ) {
    //     if( hash[i] != header.hash[i] ) {
    //         PRINT_INFO( "Hash of chunk hashes do not match\n" );
    //         break;
    //     }
    // }

exit:
    free( buffer );
    fclose( in );

    return 0;
}

static void usage( char *command, char* message) {
    PRINT_INFO( "ERROR: %s\n"
                "usage:      %s op <op args>\n"
                "op:           'encode' or 'decode'\n"
                "encode args: -n <capsulename> -d <datafile> -p <policyfile> "
                "-k <kvfile> -o <outfolder>\n"
                "\tcapsulename:  capsule name (no extension)\n"
                "\tdatafile:     input data file\n"
                "\tpolicyfile:   input policy file\n"
                "\tkvfile:       input key value store file\n"
                "\toutfolder:    output folder\n"
                "decode args: -n <capsulename>\n"
                "\tcapsulename:  capsule to decode (w/o .capsule extension)\n",
                message, command );
}

static void set_aes_key( char* keyname ) {
    // printf("keyname: %s, basename: %s\n", keyname, basename(keyname));
    set_capsule( basename(keyname), &aes_key_len, &aes_key, &aes_iv_len,
                 &aes_iv, &aes_id );
}

int main( int argc, char *argv[] ) {
    char   *op = argv[1], 
           *keyname = NULL, 
           *datafile = NULL, 
           *policyfile = NULL, 
           *kvfile = NULL, 
           *outfolder = "."; 
    int     opt, optid = 1;
    char    message[80] = "";
    char   *optparse;

    // Check to see if it is a valid op
    if (strcmp(op, "encode") == 0) {
        optparse = "n:d:p:k:o:";
    } else if (strcmp(op, "decode") == 0) {
        optparse = "n:";
    } else {
        sprintf(message, "Invalid op: %s\n", op);
        usage(argv[0], message);
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt(argc, argv, optparse)) != -1) {
            switch (opt) {
            case 'n':
                keyname = optarg;
                break;
            case 'd':
                datafile = optarg;
                break;
            case 'p':
                policyfile = optarg;
                break;
            case 'k':
                kvfile = optarg;
                break;
            case 'o':
                outfolder = optarg;
                break;
            default:
                sprintf(message, "Unknown option: %c\n", opt);
                usage( argv[0], message );
                exit(EXIT_FAILURE);
            }
    }

    if (keyname == NULL) {
        sprintf(message, "Must provide a keyname\n");
        usage( argv[0], message);
        exit(EXIT_FAILURE);
    }

    set_aes_key( keyname );

    if( strcmp( op, "encode" ) == 0 && keyname != NULL) {
        char* outpath = filename_concat(outfolder, keyname, "/");

        // Generate output files
        char *capsule = filename_concat(outpath, "capsule", "."); 
        char *ptx = filename_concat(outpath, "plt", "."); 
        char *datacopy = filename_concat(outpath, "data", "."); 
        char *policycopy = filename_concat(outpath, "policy", ".");
        char *kvstorecopy = filename_concat(outpath, "kvstore", "."); 
        char *logcopy = filename_concat(outpath, "log", ".");

        PRINT_INFO( "Concatenating %s with %s and %s into %s\n", 
                    datafile, policyfile, kvfile, ptx );
        concatenate( datafile, policyfile, kvfile, ptx, datacopy, policycopy, 
                     kvstorecopy, logcopy, keyname );

        PRINT_INFO( "Encrypting %s...\n", ptx );        
        encrypt_file( ptx );

        PRINT_INFO( "Copying contents from %s to %s and adding"
                    " a trusted capsule header...\n", 
                    ptx, capsule );
        append_header( ptx, capsule, aes_key, aes_id );

        // Free the files (they were malloc'd in concate call)
        free(capsule);
        free(outpath);
        free(ptx);
        free(datacopy);
        free(policycopy);
    } else if ( strcmp( op, "decode" ) == 0 ) {
        char* capsule = filename_concat(keyname, "capsule", ".");
        PRINT_INFO( "Decrypting %s\n", capsule );
        decrypt_file( capsule );
        free(capsule);
    }

    return 0;
}

