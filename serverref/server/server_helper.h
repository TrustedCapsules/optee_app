#ifndef SERVER_HELPER_H
#define SERVER_HELPER_H

// OS helpers
size_t 		open_file( const char* filename, char* buf, size_t len );
uint32_t 	littleEndianToUint( unsigned char *id );

// Server helpers
void registerCapsules(void);
void registerStates(void);

#endif
