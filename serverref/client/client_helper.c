#include <stdio.h>
#include <stdlib.h>
#include <socket.h>
#include <types.h>
#include <time.h>

#include "../server/fakeoptee.h"
#include "../server/linkedlist.h"
#include "../server/server_helper.h"

int createReqHeader( msgReqHeader *h, capsuleEntry *e, SERVER_REQ q, int len ) {
	h->capsuleID = littleEndianToUint( e->capsuleID );
	
	memset( h->deviceID, 0, sizeof( h->deviceID ) );
	memcpy( h->deviceID, "Dr. Jekyll", 10 );
	
	h->req = q;
	
	srand( time( NULL ) );	
	nonce = rand();
	h->nonce = nonce;	

	memset( h->hash, 0, sizeof( h->hash ) );

	h->payloadLen = len;

	unsigned char hHash[HASHLEN];
	hashData( (void*) &h, sizeof( h ), hHash, sizeof( hHash ) );
	memcpy( h->hash, hHash, sizeof( hHash ) );

	// encrypt req header
	encryptData( (void*) h, (void*) h, sizeof( msgReqHeader ), e );

	return nonce;
}

msgPayload* createReqPayload( int nonce, char* key, size_t len ) {
	msgPayload* p = (msgPayload*) malloc( sizeof( msgPayload ) + len );
	p->nonce = nonce;
	// Hash the payload
	hashData( (void*) p->payload, len, p->hash, sizeof( p->hash ) );
	memcpy( p->payload, key, len );
	
	// Encrypt the payload
	encryptData( (void*) p, (void*) p, sizeof( msgPayload ) + len, e );

	return p;	
}

int validateAndDecryptReplyHeader( int nonce, msgReplyHeader *r, capsuleEntry *e ) {
	decryptData( (void*) r, (void*) r, sizeof( r ), e );
	
	// validate nonce and hash	
	unsigned char rHash[HASHLEN];
	unsigned char dHash[HASHLEN];
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

	if( reply.reponse == FAILURE ) {
		printf( "recv(): server operation failed\n" );
		return -1;
	}
	
	return 0;
}`

msgPayload* recvPayload( int nonce, msgReplyHeader *r, capsuleEntry *e ) {
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
	if( compareHash( phash, p->hash, sizeof( phash ) ) == false ) {
		free( p );
		printf( "recv(): payload hash does not match\n" );
		return NULL;
	}

	if( p->nonce != nonce ) {
		free( payload );
		printf( "recv(): payload nonce does not match\n" );
		return NULL;
	}

	return p;
}


