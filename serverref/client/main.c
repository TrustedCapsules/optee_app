#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <types.h>
#include <time.h>

#include "../server/fakeoptee.h"
#include "../server/server_helper.h"
#include "../server/linkedlist.h"
#include "client_helper.h"

capsuleTable t = {0}; 

int connectToServer( char* ipAddr, uint16_t port ) {
	int fd = socket( AF_INET, SOCK_STREAM, 0 );
	if( fd < 0 ) {
		fprintf( stderr, "socket(): failed\n" );
		return -1;
	}

	struct sockaddr_in serverAddr;
	memset( &serverAddr, 0, sizeof( serverAddr ) );
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( port );
	inet_pton( AF_INET, ipAddr, &( serverAddr.sin_addr ) );

	if( connect( fd, (struct sockaddr *) &serverAddr, sizeof( serverAddr ) ) < 0 ) {
		fprintf( stderr, "connect(): failed\n" );
		return -1;
	}

	return fd;
}

// initCapsuleEntries register only the first capsule in manifest
void initCapsuleEntries() {
	capsuleEntry* e = (capsuleEntry*) malloc( sizeof(capsuleEntry) );
	memcpy( e.name, manifest[0].name, sizeof(manifest[0].name) );
	e->key = keyDefault;
	e->keyLen = sizeof(keyDefault);
	e->iv = ivDefault;
	e->ivLen = sizeof(ivDefault);
	e->capsuleID = littleEndianToUint( manifest[0].id );
	e->policyVerison = 0;
	e->stateTable = NULL;
	e->next = NULL;	

	t.size = 1;
	t.head = e;
	t.end = e;
}

static void usage() {
	printf( "USAGE: ./capsule_client <port>\n" );
}

void sendReqAndRecvReply( SERVER_REQ q, int fd, capsuleEntry *e, 
						  char* str, size_t strLen ) {
	// send data
	msgReqHeader h = {0};
	int nonce = createReqHeader( &h, e, q, strLen );
	ssize_t n = send( fd, (void*) h, sizeof( h ), 0 );
	if( n < 0 ) {
		printf( "send(): req header failed\n" );
		return;
	}

	// send payload
	if( strLen > 0 && str != NULL ) {
		msgPayload* toPayload = createReqPayload( nonce, str, strLen );
		n = send( fd, (void*) toPayload, sizeof( msgPayload ) + strLen );
		if( n < 0 ) {
			printf( "send(): req payload failed\n" );
			free( toPayload );
			return;
		}
		free( toPayload ); 
	}

	// recv reply
	msgReplyHeader reply;
	ssize_t r = recv( fd, (void*) reply, sizeof( reply ), 0 );
	if( r < 0 ) {
		printf( "recv(): reply header failed\n" );
		return;
	}
	if( validateAndDecryptReplyHeader( nonce, &reply, e ) == -1 ) {
		return;
	}

	// recv payload
	msgPayload* fromPayload = recvPayload( nonce, &reply, e );
	if( fromPayload == NULL ) return;

	// print payload
	printf( "payload:\n" );
	for( int i = 0; i < reply.payloadLen; i++ ) {
		printf( "%c", fromPayload->payload[i] );
	}
	printf( "\n" );

	free( fromPayload );
}


void main( int argc, char** argv ) {
	
	if( argc != 1 ) {
		usage();
	}	

	initCapsuleEntries();

	uint16_t port = strtoumax( argv[1], NULL, 10 );
	int fd = connectToServer( "127.0.0.1", port );
	if( fd == -1 ) return;

	// ECHO test with first capsule in manifest
	sendReqAndRecvReply( ECHO, fd, t->head, NULL, 0 );	

	// GET_STATE test with first capsule in manifest
	char key1[] = "credential";
	sendReqAndRecvReply( GET_STATE, fd, t->head, key1, strlen(key1) );
	char key2[] = "alreadyOpened";
	sendReqAndRecvReply( GET_STATE, fd, t->head, key2, strlen(key2) );
	char key3[] = "nonExistentKey";
	sendReqAndRecvReply( GET_STATE, fd, t->head, key3, strlen(key3) );
	
	// SET_STATE test with first capsule in manifest
	char keyval1[] = "credential:Dr.SimonHowell";
	sendReqAndRecvReply( SET_STATE, fd, t->head, keyval1, strlen(keyval1) );
	char keyval2[] = "newState:newStateVal";
	sendReqAndRecvReply( SET_STATE, fd, t->head, keyval2, strlen(keyval2) );

	// POLICY_UPDATE test with first capsule in manifest
	int version = 0;
	sendReqAndRecvReply( POLICY_UPDATE, fd, t->head, 
						 (void*) &version, sizeof(version) );
	int version = 2;
	sendReqAndRecvReply( POLICY_UPDATE, fd, t->head, 
						 (void*) &version, sizeof(version) );

	// LOG_ENTRY TEST with first capsule in manifest
	char log[] = "THIS IS A NEW LOG ENTRY\nRANDOM WORDS\n";
	sendReqAndRecvReply( POLICY_UPDATE, fd, t->head, log, strlen(log) );
}
