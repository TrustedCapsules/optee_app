#ifndef SERVER_HELPER_H
#define SERVER_HELPER_H

// OS helpers
size_t 		open_file( const char* filename, char* buf, size_t len );
size_t 		append_file( const char* filename, char *buf, size_t len );
int			policyVersion( const char* filename );
uint32_t 	littleEndianToUint( const unsigned char *id );
int 		sendData( int fd, void *buf, size_t len );
int 		recvData( int fd, void *buf, size_t len );

// Server helpers
void registerCapsules(void);
void registerStates( capsuleEntry *e, char* buf, size_t len );

// Cryptographic helpers
void encryptData( void* ptx, void *ctx, size_t len, capsuleEntry *e );
void decryptData( void* ctx, void *ptx, size_t len, capsuleEntry *e );
void hashData( void* buf, size_t lBuf, unsigned char* hash, size_t lHash );
bool compareHash( unsigned char* hash1, unsigned char* hash2, size_t lHash );

#endif
