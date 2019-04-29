#ifndef SERVER_TOMCRYPT_H
#define SERVER_TOMCRYPT_H

#include <stdbool.h>
// Cryptographic helpers
void encryptData( void* ptx, void *ctx, size_t len, capsuleEntry *e );
void decryptData( void* ctx, void *ptx, size_t len, capsuleEntry *e );
bool compareHash( unsigned char* hash1, unsigned char* hash2, size_t lHash );

#endif
