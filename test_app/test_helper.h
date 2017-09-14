#ifndef TEST_HELPER_H
#define TEST_HELPER_H

#define STR_WHENCE( wh ) \
		(wh) == SEEK_SET ? "SEEK_SET" : ( (wh) == SEEK_CUR ? "SEEK_CUR" : "SEEK_END" ) 

void abs_construct( char* dst, char* path, char* file );
int open_file( char* path, int flags );
int read_file( int fd, int offset, int whence, char* buf, int len );
int write_file( int fd, int offset, int whence, char* buf, int len );
int write_network( int fd, char* buf, int len );
int read_network( int fd, char* buf, int len );
int connect_to_server( char* IP, char* port );
int close_fd( int fd );

#endif
