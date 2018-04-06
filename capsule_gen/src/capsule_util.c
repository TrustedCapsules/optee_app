#include <stdio.h>
#include <string.h>
#include <aes_keys.h>
// #include <regex.h>
#include <capsule.h>
#include "capsule_util.h"

void parse_kvstore( unsigned char* input, size_t inlen ) {
    unsigned char* pairs[MAX_NUM_KEYS]; // Make array of maximum key, value pairs

    int last = 0,
        match_state = 0,
        start = 0,
        end = 0,
        index = 0,
        num = 0;
    size_t pair_len;
    unsigned char* delim = (unsigned char*) ";";
    bool matched = false;
    int delim_len = strlen((char*) delim);

    struct kv_pair kv_store[MAX_NUM_KEYS];

    do {
        matched = false;
        find_delimiter(input+last, inlen - last, &start, &end, &match_state, 
                       &matched, delim, delim_len);

        if (index < MAX_NUM_KEYS) {
            if (matched == true) {
                pairs[index] = malloc(start * sizeof(unsigned char));
                memcpy(pairs[index], input + last, start);
                pairs[index][start - 1] = '\0';
                last += end;
                index++;
            } else {
                pairs[index] = malloc((inlen - last) * sizeof(unsigned char));
                memcpy(pairs[index], input+last, (inlen - last));
                pairs[index][(inlen - last - 1)] = '\0';
                index++;
                break;
            }
        }
    } while(matched == true);

    delim = (unsigned char*) ":";

    for (int i = 0; i < index; i++) {
        pair_len = strlen((char*) pairs[i]);
        last = 0, start = 0, end = 0;
        matched = false;

        find_delimiter( pairs[i], pair_len, &start, &end, &match_state, 
                       &matched, delim, delim_len);

        kv_store[i].key = malloc(start * sizeof(unsigned char));
        memcpy(kv_store[i].key, pairs[i], start);
        kv_store[i].key[start - 1] = '\0';
        last += end;

        matched = false;
        find_delimiter( pairs[i]+last, pair_len - last, &start, &end, &match_state, 
                       &matched, delim, delim_len);

        kv_store[i].value = malloc((pair_len - last + 1) * sizeof(unsigned char));
        memcpy(kv_store[i].value, pairs[i] + last, (pair_len - last));
        kv_store[i].value[(pair_len - last)] = '\0';
    }

    for (int i = 0; i < index; i++) {
        printf("Pair: %d\n\tKey: %s\n\tValue: %s\n", i, kv_store[i].key, kv_store[i].value );
    }
}

/* 
 * Concatenate two strings (for generating file names)
 */
char* filename_concat(const char *name, const char *extension, const char *delimiter) {
    // Get string size, +1 for the null-terminator
    size_t size = strlen(name) + strlen(delimiter) + strlen(extension) + 1;
    char *result = malloc(size);

    if ( result == NULL ) {
        PRINT_INFO( "concat()-> malloc(%lu) failed\n", size);
    }

    // Fill in with filename and extension
    strcpy(result, name);
    strcat(result, delimiter);
    strcat(result, extension);
    return result;
}

/*
 * Processes an AES encryption/decryption operation
 */
int process_ctr_aes(const unsigned char *in, unsigned char *out,
                    size_t len, unsigned char *key, size_t keylen,
                    unsigned int counter, unsigned char* iv, 
                    unsigned int iv_len, process_func func) {
    symmetric_CTR ctr;
    unsigned int  decoded_len = 0;
    unsigned int  decrypt_len = 0;
    unsigned char in_sec[256];
    unsigned char out_sec[256];
    int           index = 15;   

    CHECK_CRYPT_OK(register_cipher(&aes_desc), "register_cipher");
    CHECK_CRYPT_OK(ctr_start(find_cipher("aes"), iv, key, keylen, 
                             0, CTR_COUNTER_BIG_ENDIAN, &ctr),
                             "ctr_start" );
    counter = counter/16;
    while( counter != 0 ) {
        ctr.ctr[index] = counter % 256;
        counter = counter / 256;
        index--;
    }
    cipher_descriptor[ctr.cipher].ecb_encrypt(ctr.ctr, 
                                              ctr.pad, 
                                              &ctr.key);

    while( decoded_len < len ) {
        if( len - decoded_len >= 256 )
            decrypt_len = 256;
        else
            decrypt_len = len - decoded_len;

        DIAGNOSTIC("%d %d %d %02x%02x%02x %02x%02x%02x\n",
                   ctr.padlen, ctr.blocklen, ctr.ctrlen, 
                   ctr.ctr[13], ctr.ctr[14], ctr.ctr[15], 
                   ctr.pad[127], ctr.pad[15], ctr.pad[0] );

        memcpy( in_sec, in+decoded_len, decrypt_len );
        CHECK_CRYPT_OK( func(in_sec, out_sec, decrypt_len, &ctr), 
                        "<<process_func>>" );
        memcpy( out+decoded_len, out_sec, decrypt_len ); 
        decoded_len += 256;
    }

    CHECK_CRYPT_OK( ctr_done(&ctr), "ctr_done" );
    CHECK_CRYPT_OK( unregister_cipher(&aes_desc), 
                    "unregister_cipher" );

    /* Clear memory */
    zeromem(&ctr, sizeof(ctr));

    return 0;
}

/*
 * Encrypts an input buffer using AES and writes the ciphertext to out
 */
int aes_encrypt(const unsigned char *in, unsigned char *out,
                size_t len, unsigned char *key, size_t keylen, 
                unsigned int ctr, unsigned char *iv, 
                unsigned int iv_len) {
    return process_ctr_aes(in, out, len, key, keylen, ctr, iv, 
                           iv_len, &ctr_encrypt);
}

/*
 * Decrypts an input buffer using AES and writes the plaintext to out
 */
int aes_decrypt(const unsigned char *in, unsigned char *out,
                size_t len, unsigned char *key, size_t keylen, 
                unsigned int ctr, unsigned char *iv, 
                unsigned int iv_len) {
    return process_ctr_aes(in, out, len, key, keylen, ctr, iv, 
                           iv_len, &ctr_decrypt);
}

/*
 * Strip away the trusted capsule header
 */
void print_header( struct TrustedCap* header, unsigned int hlen, 
                   unsigned char* key, unsigned int key_len, 
                   unsigned char* iv, unsigned int iv_len ) {

    unsigned char id[4];
    int           i;

    if( hlen != sizeof( struct TrustedCap ) ) {
        PRINT_INFO( "Print_header()->Header is wrong size %u B"
                    " instead of %lu B\n", 
                    hlen, sizeof(struct TrustedCap) );
        return; 
    }

    aes_decrypt( (const unsigned char*) header->aes_id, id, sizeof(id),
                 key, key_len, 0, iv, iv_len );

    PRINT_INFO( "Header Pad: %s\n"
                "Header Capsule Size: %u\n"
                "Header AES_ID: ", header->pad, header->capsize );
    for( i = 0; i < sizeof( id ); i++ ) {
        PRINT_INFO( "%02x", id[i] );
    }
    PRINT_INFO( "\n" );

    PRINT_INFO( "Header Hash: " );
    for( i = 0; i < sizeof( header->hash ); i++ ) {
        PRINT_INFO( "%02x", header->hash[i] );
    }
    PRINT_INFO( "\n" );
}

/*
 * Fill out the TrustedCap header
 */
void fill_header( struct TrustedCap * header, size_t fsize, 
                  unsigned char* key, unsigned int key_len, 
                  unsigned char* iv, unsigned int iv_len, 
                  unsigned char* id, unsigned char* hash,
                  unsigned int hash_len ) {

    if( hash_len != 32 ) {
        PRINT_INFO( "Fill_header()-> Hash is wrong length\n" );
    }

    memset( header, 0, sizeof( struct TrustedCap ) );

    strcpy( header->pad, TRUSTEDCAP );
    aes_encrypt( id, header->aes_id, sizeof(header->aes_id), 
                 key, key_len, 0, iv, iv_len );
    header->capsize = fsize;
    memcpy( header->hash, hash, hash_len );
}

/*
 * Encrypt and hash a chunk of data
 */
void encrypt_content( unsigned char* buffer, size_t buflen, 
                      unsigned char* key, unsigned int key_len, 
                      unsigned char* iv, unsigned int iv_len
                      ) {
                      //unsigned char* hash, size_t hashlen, 
    
    // hash_state md;

    // if( hashlen > 32 ) {
    //     PRINT_INFO( "encrypt_content()-> previously using SHA256, "
    //                 "did this change?\n" );
    // }

    // sha256_init( &md );
    // sha256_process( &md, (const unsigned char*) buffer, buflen );
    // sha256_done( &md, hash );

    aes_encrypt( (const unsigned char* ) buffer, buffer, buflen, 
                 key, key_len, 0, iv, iv_len );

}

/*
 * Decrypt and calculate the hash of a chunk of data
 */
void decrypt_content( unsigned char *buffer, size_t buflen, 
                      unsigned char *key, unsigned int key_len, 
                      unsigned char *iv, unsigned int iv_len
                      ) {
                      // unsigned char *hash, size_t hashlen, 
    // hash_state     md;
    // unsigned char  hash_calc[32];
    // int            n;

    // if( hashlen > 32 ) {
    //     PRINT_INFO( "decrypt_content()-> previously using SHA256, "
    //                 "did this change?\n" );
    // }

    aes_decrypt( (const unsigned char*) buffer, buffer, 
                 buflen, key, key_len, 0, iv, iv_len );

    // sha256_init( &md );
    // sha256_process( &md, (const unsigned char*) buffer, buflen );
    // sha256_done( &md, hash_calc);
}

/*
 * Finds the delimiter in a string
 */ 
void find_delimiter( unsigned char* buf, size_t blen, int* dstart, 
                     int* dend, int* state, bool *matched, 
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

/*
 * parse decrypted capsule data
 */
void populate_parts( unsigned char* buf, int len, struct range parts[4] ) {

    // regex_t re;
    // regmatch_t pm;
    int last = 0, index = 0, start = 0, end = 0, match_state = 0;
    // int error = 0;
    bool matched;
    unsigned char delimiter[DELIMITER_SIZE] = DELIMITER;

    // (void) regcomp(&re, DELIMITER, 0);

    do {
        matched = false;
        // error = regexec(&re, (const char*) buf+last, 1, &pm, REG_NOTBOL);
        find_delimiter(buf+last, len - last, &start, &end, &match_state, &matched,
                       delimiter, DELIMITER_SIZE);
        if (index < 4) {
            if (matched == true) {
                parts[index].start = last;
                parts[index].end = last + start;
                // printf("Found string (%.*s)\n", (pm.rm_so), buf+last);
                last += end;
                index++;
            } else {
                parts[index].start = last;
                parts[index].end = len;
                index++;
                break;
            }
        }
    } while(matched == true);

    // printf("[populate_parts] Ranges:\n");
    // for (int i = 0; i < 4; i++) {
    //  printf("%d: %d, %d\n", i, parts[i].start, parts[i].end);
    // }
}

void print_parts( unsigned char * buf, struct range parts[4] ){
    for (int i = 0; i < 4; i++) {
        char* part;
        switch (i) {
            case 0:
                part = "Policy";
                break;
            case 1:
                part = "KV Store";
                break;
            case 2:
                part = "Log";
                break;
            case 3:
                part = "Data";
                break;
        }
        printf("%s: %d, %d\n", part, parts[i].start, parts[i].end);
        printf("%.*s\n\n", parts[i].end - parts[i].start, buf + parts[i].start);
    }
}

// TODO: remove chunk size
void set_capsule( char* keyname, unsigned int* key_len, 
                  unsigned char** key, unsigned int* iv_len, 
                  unsigned char** iv, //unsigned int* chunk_size, 
                  unsigned char** id ) {

    int i, found = 0;

    *key_len = sizeof( key_std );
    *key = key_std;
    *iv_len = sizeof( iv_std );
    *iv = iv_std;

    for( i = 0; i < sizeof(capsule_data_array) / sizeof( struct capsule_data ); i++ ) {
        // printf( "%s %s\n", keyname, capsule_data_array[i].str );
        if( strcmp( keyname, (const char*) capsule_data_array[i].str ) == 0 ) {
            *id = capsule_data_array[i].id;
            found = 1;
            break;
        }
    }

    if( found == 0 ) {
        PRINT_INFO( "CAPSULE DATA FOR (%s) NOT FOUND\n", keyname );
        exit(1);
    }
}       
