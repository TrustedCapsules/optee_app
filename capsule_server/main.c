#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <aes_keys.h>
#include <amessage.pb-c.h>
#include <capsule_util.h>
#include "main.h"
#include "echo_process.h"
#include "capsule_process.h"
#include "server_op.h"

int policy_state = -1;

static void* get_in_addr( struct sockaddr *sa ) {
	if( sa->sa_family == AF_INET ) {
		return &((( struct sockaddr_in* ) sa )->sin_addr );
	}

	return &((( struct sockaddr_in6*) sa)->sin6_addr );
}

static int handle_connections( int sockfd, enum MODE mode ) {
	struct sockaddr_storage   their_addr;
	socklen_t    			  sin_size = sizeof(their_addr);
	char 					  s[INET6_ADDRSTRLEN];
	int                       new_fd;

	PRINT_INFO( "Server: waiting for connections...\n" );
	while(1) {
		
		new_fd = accept( sockfd, (struct sockaddr *) &their_addr,
						 &sin_size );
		policy_state++;
		if( new_fd == -1 ) {
			PRINT_ERR( "ACCEPT() Error: %s\n", strerror( errno ) );
			continue;
		}

		inet_ntop( their_addr.ss_family,
				   get_in_addr( (struct sockaddr*) &their_addr ),
				   s, sizeof( s ) );

		PRINT_INFO( "Server: got connection from %s\n", s );
		
		/* FIXME: change to pthreads */
		if( !fork() ) {
			close( sockfd );
			if( mode == ECHO_SIMPLE_MODE ) {
				echo_simple_process( new_fd );
			} else if ( mode == ECHO_ENC_SER_MODE ){
				echo_enc_ser_process( new_fd );				
			} else {
				capsule_process( new_fd );
			}
			PRINT_INFO( "Server: closed connection %s\n", s );
			close( new_fd );
			exit(0);
		}
		close( new_fd );
	}
	return 0;
}

static void set_hints( struct addrinfo *hints ) {
	memset( hints, 0, sizeof(struct addrinfo) );
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_STREAM;
	hints->ai_flags = AI_PASSIVE;
}


static int make_connection( struct addrinfo *servinfo,
	   						struct addrinfo **p ) {
	int              sockfd, rv;
	int              yes = 1;

	for( *p = servinfo; *p != NULL; *p = (*p)->ai_next ) {
		
		sockfd = socket( (*p)->ai_family, (*p)->ai_socktype, (*p)->ai_protocol );
		if( sockfd == -1 ) {
			PRINT_ERR( "SOCKET() Error: %s\n", strerror( errno ) );
			continue;
		}	

		rv = setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, 
						 &yes, sizeof(int) );
		if( rv == -1 ) {
			PRINT_ERR( "SETSOCKOPT() Error: %s\n", strerror( errno ) );
		}

		rv = bind( sockfd, (*p)->ai_addr, (*p)->ai_addrlen );
		if( rv == -1 ) {
			close( sockfd );
			PRINT_ERR( "BIND() Error: %s\n", strerror( errno ) );
			continue;
		}

		break;
	}

	freeaddrinfo( servinfo );
	return sockfd;
}

static void print_usage() {
	PRINT_INFO( "USAGE: ./capsule_server PORT MODE\n"
			    "PORT-> integer\n"
				"MODE-> ECHO_SIMPLE ECHO_ENC_SER CAPSULE\n" );
}

int main( int argc, char** argv ) {

	struct addrinfo		hints, *servinfo, *p = NULL;
	char               *service;
	int                 rv, sockfd;
	enum MODE           mode;

	if( argc != 3 ) {
		print_usage();
		return -1;
	}

	if( strcmp( argv[2], "ECHO_SIMPLE" ) == 0 ) {
		mode = ECHO_SIMPLE_MODE; 		
	} else if( strcmp( argv[2], "CAPSULE" ) == 0 ) {
		mode = CAPSULE_MODE;
	} else if( strcmp( argv[2], "ECHO_ENC_SER" ) == 0 )   {
		mode = ECHO_ENC_SER_MODE;
	} else {
		print_usage();
		return -1;
	}

	register_capsule_entry();
	register_state();

	set_hints( &hints );
	service = argv[1];

	if( (rv = getaddrinfo( NULL, service, &hints, &servinfo ) ) != 0 ) {
		PRINT_ERR( "getaddrinfo: %s\n", gai_strerror(rv) );
		return -1;
	}

	sockfd = make_connection( servinfo, &p );	
	if( p == NULL ) {
		PRINT_ERR( "GETADDRINFO() Error: Nothing to bind to\n" );
		return -1;
	}

	if( listen(sockfd, 10) == -1 ) {
		PRINT_ERR( "LISTEN() Error: %s\n", strerror( errno ) );
		return -1;
	}

	return handle_connections( sockfd, mode );
}
