#ifndef SERVER_HELPER_H
#define SERVER_HELPER_H

// OS helpers
size_t 		open_file( const char* filename, char* buf, size_t len );
size_t 		append_file( const char* filename, char *buf, size_t len );
int			policyVersion( const char* filename );
int 		sendData( int fd, void *buf, size_t len );
int 		recvData( int fd, void *buf, size_t len );

// Server helpers
void registerCapsules(void);
void registerStates( capsuleEntry *e, char* buf, size_t len );

#endif
