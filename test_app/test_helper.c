#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include "test_app.h"

void abs_construct( char* dst, char* path, char* file ) {
	if( strlen( path ) + strlen( file ) + 2 > MAX_PATH ) {
		PRINT_INFO( "The absolute path is greater than PATH_MAX\n" );
		return;
	}
	strcpy( dst, path );
	strcat( dst, "/" );
	strcat( dst, file );
}

int open_file( char* path, int flags ) {
	return openat( AT_FDCWD, path, flags );
}


int read_file( int fd, int offset, int whence, char* buf, int len ) {
	int	ns = lseek( fd, offset, whence );
	if( ns < 0 ) {
		return ns;
	}

	return read( fd, buf, len );
}

int write_file( int fd, int offset, int whence, char* buf, int len ) {
	int	ns = lseek( fd, offset, whence );
	if( ns < 0 ) {
		return ns;
	}

	return write( fd, buf, len );
}

int write_network( int fd, char* buf, int len ) {
	return write( fd, buf, len );
}

int read_network( int fd, char* buf, int len ) {
	return read( fd, buf, len );
}

int connect_to_server( char* IP, char* port ) {
	int 			sockfd;
	struct addrinfo hints, *servinfo, *p;
	int             rv;

	memset( &hints, 0, sizeof( hints ) );
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	rv = getaddrinfo( IP, port, &hints, &servinfo );
	if( rv != 0 ) {
		PRINT_ERR( "Connect_to_server() Error: Failed to connect "
				   "to %s/%s\n", IP, port );
		return -1;
	}

	for( p = servinfo; p != NULL; p = p->ai_next ) {
		sockfd = socket( p->ai_family, p->ai_socktype, p->ai_protocol );
		if( sockfd < 0 ) {
			continue;
		}
			
		rv = connect( sockfd, p->ai_addr, p->ai_addrlen );
		if( rv < 0 ) {
			close( sockfd );
			continue;
		}
		break;
	}

	if( p == NULL ) {
		PRINT_ERR( "Connect_to_server() Error: Failed to connect "
				   "to %s/%s\n", IP, port );
		return -1;
	}

	freeaddrinfo( servinfo );

	return sockfd;
}

int close_fd( int fd ) {
	return close( fd );
}


