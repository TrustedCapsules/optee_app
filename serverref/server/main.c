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
#include <pthread.h>
#include <signal.h>

#include <capsuleCommon.h>
#include <capsuleServerProtocol.h>

#include "../common/entry.h"
#include "hash.h"
#include "linkedlist.h"
#include "server_op.h"
#include "server_helper.h"

static void* get_in_addr( struct sockaddr *sa ) {
	if( sa->sa_family == AF_INET ) {
		return &((( struct sockaddr_in* ) sa )->sin_addr );
	}

	return &((( struct sockaddr_in6*) sa)->sin6_addr );
}

static int handleConnections( int sockfd ) {
	struct sockaddr_storage   their_addr;
	socklen_t    			  sin_size = sizeof(their_addr);
	char 					  s[INET6_ADDRSTRLEN];
	int                       new_fd;

	printf( "Server waiting for connections...\n" );
	while(1) {
		
		new_fd = accept( sockfd, (struct sockaddr *) &their_addr,
						 &sin_size );
		if( new_fd == -1 ) {
			fprintf( stderr, "accept() error: %s\n", strerror( errno ) );
			continue;
		}

		inet_ntop( their_addr.ss_family,
				   get_in_addr( (struct sockaddr*) &their_addr ),
				   s, sizeof( s ) );

		printf( "Server got connection from %s\n\n", s );
		
		pthread_t thread_id;
        if( pthread_create( &thread_id , NULL , handleCapsule , (void*) &new_fd ) < 0) {
            fprintf( stderr, "pthread_create() could not create new thread\n" );
            continue;
        }
	}

	//TODO: pthread_join should be called to collect pthreads so parent doesn't exit 
	//		before child
	return 0;
}

static void set_hints( struct addrinfo *hints ) {
	memset( hints, 0, sizeof(struct addrinfo) );
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_STREAM;
	hints->ai_flags = AI_PASSIVE;
}


static int makeConnection( struct addrinfo *servinfo,
	   						struct addrinfo **p ) {
	int              sockfd, rv;
	int              yes = 1;

	for( *p = servinfo; *p != NULL; *p = (*p)->ai_next ) {
		
		sockfd = socket( (*p)->ai_family, (*p)->ai_socktype, (*p)->ai_protocol );
		if( sockfd == -1 ) {
			fprintf( stderr, "socket() error: %s\n", strerror( errno ) );
			continue;
		}	

		rv = setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, 
						 &yes, sizeof(int) );
		if( rv == -1 ) {
			fprintf( stderr, "setsockopt() error: %s\n", strerror( errno ) );
		}

		rv = bind( sockfd, (*p)->ai_addr, (*p)->ai_addrlen );
		if( rv == -1 ) {
			close( sockfd );
			fprintf( stderr, "bind() error: %s\n", strerror( errno ) );
			continue;
		}

		break;
	}

	freeaddrinfo( servinfo );
	return sockfd;
}

static void print_usage() {
	printf( "USAGE: ./capsule_server <port>\n" );
}

int main( int argc, char** argv ) {

	struct addrinfo		hints, *servinfo, *p = NULL;
	char               *service;
	int                 rv, sockfd;

	if( argc != 2 ) {
		print_usage();
		return -1;
	}

	registerCapsules();

	set_hints( &hints );
	service = argv[1];

	if( (rv = getaddrinfo( NULL, service, &hints, &servinfo ) ) != 0 ) {
		fprintf( stderr, "getaddrinfo: %s\n", gai_strerror(rv) );
		return -1;
	}

	sockfd = makeConnection( servinfo, &p );	
	if( p == NULL ) {
		fprintf( stderr, "getaddrinfo() error: nothing to bind to\n" );
		return -1;
	}

	if( listen(sockfd, 10) == -1 ) {
		fprintf( stderr, "listen() error: %s\n", strerror( errno ) );
		return -1;
	}

	return handleConnections( sockfd );
}
