#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

// TODO: remove dependency when common is re-written
#include <capsule_util.h>

#include "../server/fakeoptee.h"
#include "../server/hash.h"
#include "../server/linkedlist.h"
#include "../server/server_helper.h"

void printHash( const unsigned char* h, size_t len ) {
	for( int i = 0; i < len; i++ ) {
		if( i != 0 && i % 4 == 0 ) {
			printf( " " );
		}
		printf( "%02x", h[i] );
	}
}

void printChars( const char* h, size_t len ) {
	for( int i = 0; i < len; i++ ) {
		printf( "%c", h[i] );
	}
}

int createReqHeader( msgReqHeader *h, capsuleEntry *e, SERVER_REQ q, int len ) {
	h->capsuleID = e->capsuleID;
	
	memset( h->deviceID, 0, sizeof( h->deviceID ) );
	memcpy( h->deviceID, "Dr. Jekyll", 10 );
	
	h->req = q;
	
	srand( time( NULL ) );	
	int nonce = rand();
	h->nonce = nonce;	

	memset( h->hash, 0, sizeof( h->hash ) );

	h->payloadLen = len;
	
	unsigned char hHash[HASHLEN] = {0};
	hashData( (void*) h, sizeof( msgReqHeader ), hHash, sizeof( hHash ) );
	memcpy( h->hash, hHash, sizeof( hHash ) );
	
	/*
	printf( "capsuleSearch(): decrypted header\n");
	printf( "\tcapsuleID = 0x%x\n", h->capsuleID );
	printf( "\tdeviceID = " );
	printChars( h->deviceID, DEVICE_ID_LEN );
	printf( "\n" );
	printf( "\treq = %d\n", h->req );
	printf( "\tnonce = %d\n", h->nonce );
	printf( "\thash = " );
	printHash( hHash, HASHLEN );
	printf( "\n" );
	printf( "\tpayload length= %zu\n", h->payloadLen );
	*/

	// encrypt req header
	encryptData( (void*) h, (void*) h, sizeof( msgReqHeader ), e );

	return nonce;
}

msgPayload* createReqPayload( int nonce, char* key, size_t len, capsuleEntry *e ) {
	msgPayload* p = (msgPayload*) malloc( sizeof( msgPayload ) + len );
	p->nonce = nonce;
	memcpy( p->payload, key, len );
	// Hash the payload
	hashData( (void*) p->payload, len, p->hash, sizeof( p->hash ) );
	
	// Encrypt the payload
	encryptData( (void*) p, (void*) p, sizeof( msgPayload ) + len, e );

	return p;	
}

int validateAndDecryptReplyHeader( int nonce, msgReplyHeader *r, capsuleEntry *e ) {
	decryptData( (void*) r, (void*) r, sizeof( msgReplyHeader ), e );
	
	// validate nonce and hash	
	unsigned char rHash[HASHLEN];
	unsigned char dHash[HASHLEN] = {0};
	memcpy( rHash, r->hash, sizeof( r->hash ) );
	memset( r->hash, 0, sizeof( r->hash ) );
	hashData( (void*) r, sizeof( msgReplyHeader ), dHash, sizeof( dHash ) );
	if( compareHash( rHash, dHash, sizeof(dHash) ) == false ) {
		printf( "recv(): header hash does not match\n" );
		return -1;
	}

	if( r->nonce != nonce ) {
		printf( "recv(): header nonce does not match\n" );
		return -1;
	}

	if( r->response == FAILURE ) {
		printf( "recv(): server operation failed\n" );
		return -1;
	}
	
	return 0;
}

msgPayload* recvPayload( int fd, int nonce, msgReplyHeader *r, capsuleEntry *e ) {
	if( r->payloadLen <= 0 ) {
		return NULL;
	}

	msgPayload* p = (msgPayload*) malloc( sizeof( msgPayload ) + r->payloadLen );
	ssize_t n = recv( fd, (void*) p, sizeof( msgPayload ) + r->payloadLen, 0 );
	if( n < 0 ) {
		printf( "recv(): payload failed\n" );
		free( p );
		return NULL;
	}

	// decrypt payload
	decryptData( (void*) p, (void*) p, sizeof( msgPayload ) + r->payloadLen, e );
	
	// validate nonce and hash
	unsigned char pHash[HASHLEN];
	hashData( (void*) p->payload, r->payloadLen, pHash, sizeof( pHash ) );
	if( compareHash( pHash, p->hash, sizeof( pHash ) ) == false ) {
		free( p );
		printf( "recv(): payload hash does not match\n" );
		return NULL;
	}

	if( p->nonce != nonce ) {
		free( p );
		printf( "recv(): payload nonce does not match\n" );
		return NULL;
	}

	return p;
}


