#include <stdio.h>
#include <string.h>
#include <aes_keys.h>
#include <capsule.h>
#include "capsule_util.h"

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
 * Encrypts a key using RSA and writes the result to out

int rsa_encrypt(const unsigned char *in, size_t inlen,
		unsigned char *out, size_t *outlen, rsa_key *key) {
	int hash_idx, prng_idx;

	CHECK_CRYPT_OK(register_prng(&sprng_desc), "register_prng");

	ltc_mp = tfm_desc;
	CHECK_CRYPT_OK(register_hash(&sha1_desc), "register_hash");

	hash_idx = find_hash("sha1");
	prng_idx = find_prng("sprng");

	CHECK_CRYPT_OK(
			rsa_encrypt_key(in, inlen, out, outlen, NULL, 0, NULL,
				prng_idx, hash_idx, key),
			"rsa_encrypt_key"
		);

	CHECK_CRYPT_OK(unregister_hash(&sha1_desc), "unregister_hash");
	CHECK_CRYPT_OK(unregister_prng(&sprng_desc), "unregister_prng");

	return 0;
}
 */
/*
 * Decrypts a key using RSA and writes the result to out

int rsa_decrypt(const unsigned char *in, size_t inlen,
		unsigned char *out, size_t *outlen, int *res, rsa_key *key) {
	int hash_idx;

	ltc_mp = tfm_desc;
	CHECK_CRYPT_OK(register_hash(&sha1_desc), "register_hash");

	hash_idx = find_hash("sha1");
	printf("RSA_DECRYPT(): hash index %d\n", hash_idx);

	CHECK_CRYPT_OK(
			rsa_decrypt_key(in, inlen, out, outlen, NULL, 0,
				hash_idx, res, key),
			"rsa_decrypt_key"
		);

	CHECK_CRYPT_OK(unregister_hash(&sha1_desc), "unregister_hash");

	return 0;
}
 */
/*
 * Loads an rsa key from a .DER file

int load_rsa_key(char *file_name, rsa_key *key) {
	FILE *fp;
	unsigned char buffer[2048];
	size_t len = 0;

	fp = fopen(file_name, "r");
	if (fp != NULL) {
		len = fread(buffer, sizeof(char), 2048, fp);
		printf( "LOAD_RSA_KEY(): .der file length %lu\n", len );
		fclose(fp);
	}

	ltc_mp = tfm_desc;
	CHECK_CRYPT_OK(rsa_import(buffer, len, key), "rsa_import");

	return 0;
}
 */
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
			   	  unsigned int hash_len	) {

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
					  unsigned char* hash, size_t hashlen, 
					  unsigned char* key, unsigned int key_len, 
					  unsigned char* iv, unsigned int iv_len, 
					  unsigned int chunk_size, bool last ) {
	hash_state md;

	if( buflen < chunk_size && last == false ) {
		PRINT_INFO( "encrypt_content()-> buffer size less than"
					" chunk size\n" );
		return;
	}

	if( buflen > chunk_size ) {
		PRINT_INFO( "encrypt_content()-> buffer is larger than"
					" chunk size, I hope you are buffering on"
					" the other side\n" );
	}

	if( hashlen > 32 ) {
		PRINT_INFO( "encrypt_content()-> previously using SHA256, "
					"did this change?\n" );
	}

	sha256_init( &md );
	sha256_process( &md, (const unsigned char*) buffer, buflen );
	sha256_done( &md, hash );

	aes_encrypt( (const unsigned char* ) buffer, buffer, buflen, 
				 key, key_len, 0, iv, iv_len );

}

/*
 * Decrypt and calculate the hash of a chunk of data
 */
void decrypt_content( unsigned char *buffer, size_t buflen, 
					  unsigned char *hash, size_t hashlen, 
					  unsigned char *key, unsigned int key_len, 
					  unsigned char *iv, unsigned int iv_len, 
					  unsigned int chunk_size,
					  bool last, int block ) {

	hash_state     md;
	unsigned char  hash_calc[32];
	int            n;

	if( buflen < chunk_size && last == false ) {
		PRINT_INFO( "decrypt_content()-> buffer size %lu B less than"
					" chunk size %u B\n", buflen, chunk_size );
		return;
	}

	if( buflen > chunk_size ) {
		PRINT_INFO( "decrypt_content()-> buffer size %lu B larger than"
					" chunk size %u B, I hope you are buffering on"
					" the other side\n", buflen, chunk_size );
	}

	if( hashlen > 32 ) {
		PRINT_INFO( "decrypt_content()-> previously using SHA256, "
					"did this change?\n" );
	}

	aes_decrypt( (const unsigned char*) buffer, buffer, 
				 buflen, key, key_len, 0, iv, iv_len );

	sha256_init( &md );
	sha256_process( &md, (const unsigned char*) buffer, buflen );
	sha256_done( &md, hash_calc);

	for( n = 0; n < hashlen; n++ ) {
		if( hash[n] != hash_calc[n] ) {
			PRINT_INFO( "Encrypt_content()-> hash at block"
						" %d does not match: %02x vs. %02x\n", 
						block, hash[n], hash_calc[n] );
			return;
		}
	}	
}

/*
 * parse decrypted capsule data
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

// TODO: remove chunk size
void set_capsule( char* keyname, unsigned int* key_len, 
				  unsigned char** key, unsigned int* iv_len, 
				  unsigned char** iv, unsigned int* chunk_size, 
				  unsigned char** id ) {

	int 	i, found = 0;

	*key_len = sizeof( key_std );
	*key = key_std;
	*iv_len = sizeof( iv_std );
	*iv = iv_std;

	for( i = 0; 
			i < sizeof(capsule_data_array) / sizeof( struct capsule_data ); 
			   i++ ) {
		//printf( "%s %s\n", keyname, capsule_data_array[i].str );
		if( strcmp( keyname, (const char*) capsule_data_array[i].str ) == 0 ) {
			*chunk_size = capsule_data_array[i].chunk_size;
			*id = capsule_data_array[i].id;
			found = 1;
			break;
		}
	}

	if( found == 0 ) {
		PRINT_INFO( "CAPSULE DATA NOT FOUND\n" );
		exit(1);
	}
}		
