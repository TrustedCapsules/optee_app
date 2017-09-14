#ifndef CAPSULE_GEN_H
#define CAPSULE_GEN_H

void append_header( char* infile, char* outfile, unsigned char* aes_key,
					unsigned char* aes_id );
void strip_header( FILE* in, unsigned char* aes_key, 
				   struct TrustedCap *h );
void concatenate( char* datafile, char* policyfile, char* ptx, 
				  char* datacopy, char* policycopy	);
int encrypt_file( char* ptx );
int decrypt_file( char* ctx );

#endif /* CAPSULE_GEN_H */
