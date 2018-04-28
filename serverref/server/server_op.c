#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>

// TODO: remove dependency once common is re-written
#include <capsule_util.h>

#include "fakeoptee.h"
#include "hash.h"
#include "linkedlist.h"
#include "server_helper.h"

extern capsuleTable* capsules;

void reply( int fd, msgReqHeader *reqHeader, capsuleEntry *e, 
			SERVER_REPLY sr, size_t payloadLen, char* payload ) {
	
	msgReplyHeader replyHeader;
	unsigned char 	hHash[HASHLEN];
	
	// Create header
	replyHeader.capsuleID = reqHeader->capsuleID;
	replyHeader.response = sr;
	replyHeader.nonce = reqHeader->nonce;
	replyHeader.payloadLen = payloadLen;
	memset( replyHeader.hash, 0, sizeof(replyHeader.hash) );

	hashData( (void*) &replyHeader, sizeof(replyHeader), 
			  hHash, sizeof(hHash) );
	memcpy( replyHeader.hash, hHash, sizeof(hHash) );

	encryptData( (void*) &replyHeader, 
				 (void*) &replyHeader, 
				 sizeof(replyHeader), e );
	
	int nw = sendData( fd, (void*) &replyHeader, sizeof(replyHeader) );
	if( nw != sizeof( replyHeader ) ) {
		return;
	}

	// Create payload
	if( payloadLen > 0 ) {
		msgPayload 	 *p = ( msgPayload* ) malloc( sizeof( msgPayload ) + payloadLen );
		if( p == NULL ) return;
		p->nonce = reqHeader->nonce;
		hashData( (void*) payload, payloadLen, p->hash, sizeof(p->hash) );
		memcpy( p->payload, payload, payloadLen );

		encryptData( (void*) p, (void*) p, sizeof( msgPayload ) + payloadLen, e );
		sendData( fd, (void*) p, sizeof( msgPayload ) + payloadLen );
		free( p );
	}
}

msgPayload* recvPayload( int fd, msgReqHeader *reqHeader, capsuleEntry *e ) {
	unsigned char hash[HASHLEN];
	size_t 		  payloadLen = reqHeader->payloadLen;	
	msgPayload *p = ( msgPayload* ) malloc( sizeof( msgPayload ) + payloadLen );	
	int nr = recvData( fd, (void*) p, sizeof( msgPayload ) + payloadLen );
	if( nr != (int) sizeof( msgPayload ) + payloadLen ) {
		free( p );
		return NULL;
	}
	
	decryptData( (void*) p, (void*) p, sizeof( msgPayload ) + payloadLen, e );
	hashData( (void*) p->payload, payloadLen, hash, sizeof(hash) );
	if( compareHash( hash, p->hash, sizeof(hash) ) == false ) {
		free( p );
		return NULL;
	}

	if( reqHeader->nonce != p->nonce ) {
		free( p );
		return NULL;
	}
	
	return p;
}

void handleEcho( int fd, msgReqHeader *reqHeader, capsuleEntry *e ) {
	reply( fd, reqHeader, e, SUCCESS, 0, NULL );
}

void handleGetState( int fd, msgReqHeader *reqHeader, capsuleEntry *e ) {
	msgPayload *p = recvPayload( fd, reqHeader, e );
	if( p == NULL ) {
		reply( fd, reqHeader, e, FAILURE, 0, NULL );
		return;
	}

	pthread_mutex_lock( &e->stateMapMutex );	
	stateEntry *s = stateSearch( e->stateMap, p->payload, reqHeader->payloadLen );
	pthread_mutex_unlock( &e->stateMapMutex );	
	if( s == NULL ) {
		reply( fd, reqHeader, e, FAILURE, 0, NULL );
	}

	reply( fd, reqHeader, e, SUCCESS, strlen( s->value ), s->value ); 

	free( p );
}

void handleSetState( int fd, msgReqHeader *reqHeader, capsuleEntry *e ) {
	msgPayload *p = recvPayload( fd, reqHeader, e );
	if( p == NULL ) {
		reply( fd, reqHeader, e, FAILURE, 0, NULL );
		return;
	} 

	pthread_mutex_lock( &e->stateMapMutex );	
	registerStates( e, p->payload, reqHeader->payloadLen );
	pthread_mutex_unlock( &e->stateMapMutex );	

	reply( fd, reqHeader, e, SUCCESS, 0, NULL );	
	free( p );
}

void handlePolicyUpdate( int fd, msgReqHeader *reqHeader, capsuleEntry *e ) {
	msgPayload *p = recvPayload( fd, reqHeader, e );
	if( p == NULL ) {
		reply( fd, reqHeader, e, FAILURE, 0, NULL );
		return;
	}
	
	uint32_t version = littleEndianToUint( (const unsigned char*) p->payload );
	char	 payload[POLICY_MAX_SIZE] = {0};
	size_t   payloadLen = 0;	
	if( version != e->policyVersion ) {
		char policyFile[255] = {0};
		memcpy( policyFile, "../server_capsules/", 19 );
		strcat( policyFile, e->name );
		strcat( policyFile, ".policy" );	
		payloadLen = open_file( policyFile, payload, POLICY_MAX_SIZE );
		if( payloadLen < 0 ) {
			reply( fd, reqHeader, e, FAILURE, 0, NULL );
			free( p );
			return;
		}
	}
		
	reply( fd, reqHeader, e, SUCCESS, payloadLen, 
		   payloadLen == 0 ? NULL : payload );
	free( p );	
}

void handleLog( int fd, msgReqHeader *reqHeader, capsuleEntry *e ) {
	msgPayload *p = recvPayload( fd, reqHeader, e );
	if( p == NULL ) {
		reply( fd, reqHeader, e, FAILURE, 0, NULL );
		return;
	}

	char logFile[255] = {0};
	memcpy( logFile, "../server_capsules/", 19 );
	strcat( logFile, e->name );
	strcat( logFile, ".log" );	
	size_t len = append_file( logFile, p->payload, reqHeader->payloadLen );
	
	reply( fd, reqHeader, e, 
		   len == reqHeader->payloadLen ? SUCCESS : FAILURE, 
		   0, NULL );
	free( p );	
}

void handleCapsule( int fd ) {
	msgReqHeader 	  h = {0};
	unsigned char hHash[HASHLEN];
	unsigned char dHash[HASHLEN];

	int nr = recvData( fd, (void*) &h, sizeof(h) );
	if( nr != (int) sizeof(h) ) {
		return;
	}

	capsuleEntry *e = capsuleSearch( capsules, &h );
	if( e == NULL ) { 
		return;
	}
	
	memcpy( dHash, h.hash, sizeof(dHash) );
	memset( h.hash, 0, sizeof(h.hash) );
	hashData( (void*) &h, sizeof( h ), hHash, sizeof(hHash) );
	if( compareHash( hHash, dHash, sizeof(hHash) ) == false ) {
		reply( fd, &h, e, FAILURE, 0, NULL );
		return;
	}

	switch( h.req ) {
		case ECHO: 
			handleEcho( fd, &h, e );
			return;
		case GET_STATE: 
			handleGetState( fd, &h, e );
			return;
		case SET_STATE: 
			handleSetState( fd, &h, e );
			return;
		case POLICY_UPDATE: 
			handlePolicyUpdate( fd, &h, e );
			return;
		case LOG_ENTRY: 
			handleLog( fd, &h, e );
			return;
		default: 
			 reply( fd, &h, e, FAILURE, 0, NULL );
	}
}
