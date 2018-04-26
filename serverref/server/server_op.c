#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <capsule_util.h>

#include "fakeoptee.h"
#include "hash.h"
#include "server_helper.h"

extern capsuleTable* capsules;

void reply( int fd, msgHeader *reqHeader, capsuleEntry *e, 
			SERVER_REPLY sr, size_t payloadLen, char* payload ) {
	
	msgReplyHeader replyHeader;
	
	// Create header
	replyHeader.capsuleID = reqHeader->capsuleID;
	replyHeader.response = sr;
	replyHeader.nonce = reqHeader->encHeader.nonce;
	replyHeader.payloadLen = payloadLen;
	memset( replyHeader.hash, 0, sizeof(replyHeader.hash) );

	hashData( (void*) &replyHeader, sizeof(replyHeader), 
			  replyHeader.hash, sizeof(replyHeader.hash) );

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
		p->nonce = reqHeader->encHeader.nonce;
		hashData( (void*) payload, payloadLen, p->hash, sizeof(p->hash) );
		memcpy( p->payload, payload, payloadLen );

		encryptData( (void*) p, (void*) p, sizeof( msgPayload ) + payloadLen, e );
		sendData( fd, (void*) p, sizeof( msgPayload ) + payloadLen );
		free( p );
	}
}

msgPayload* recvPayload( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
	unsigned char hash[HASHLEN];
	size_t 		  payloadLen = reqHeader->encHeader.payloadLen;	
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

	if( reqHeader->encHeader.nonce != p->nonce ) {
		free( p );
		return NULL;
	}
	
	return p;
}

void handleEcho( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
	reply( fd, reqHeader, e, SUCCESS, 0, NULL );
}

void handleGetState( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
	msgPayload *p = recvPayload( fd, reqHeader, e );
	if( p == NULL ) {
		reply( fd, reqHeader, e, FAILURE, 0, NULL );
		return;
	}
	
	stateEntry *s = stateSearch( e->stateMap, p->payload, 
								 reqHeader->encHeader.payloadLen );
	if( s == NULL ) {
		reply( fd, reqHeader, e, FAILURE, 0, NULL );
	}

	reply( fd, reqHeader, e, SUCCESS, strlen( s->value ), s->value ); 

	free( p );
}

void handleSetState( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
	msgPayload *p = recvPayload( fd, reqHeader, e );
	if( p == NULL ) {
		reply( fd, reqHeader, e, FAILURE, 0, NULL );
		return;
	} 

	registerStates( e, p->payload, reqHeader->encHeader.payloadLen );

	reply( fd, reqHeader, e, SUCCESS, 0, NULL );	
	free( p );
}

void handlePolicyUpdate( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
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

void handleLog( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
	msgPayload *p = recvPayload( fd, reqHeader, e );
	if( p == NULL ) {
		reply( fd, reqHeader, e, FAILURE, 0, NULL );
		return;
	}

	char logFile[255] = {0};
	memcpy( logFile, "../server_capsules/", 19 );
	strcat( logFile, e->name );
	strcat( logFile, ".log" );	
	size_t len = append_file( logFile, p->payload, reqHeader->encHeader.payloadLen );
	
	reply( fd, reqHeader, e, 
		   len == reqHeader->encHeader.payloadLen ? SUCCESS : FAILURE, 
		   0, NULL );
	free( p );	
}

void handleCapsule( int fd ) {
	msgHeader 	  h = {0};
	unsigned char hHash[HASHLEN];
	unsigned char dHash[HASHLEN];

	int nr = recvData( fd, (void*) &h, sizeof(h) );
	if( nr != (int) sizeof(h) ) {
		return;
	}

	capsuleEntry *e = capsuleSearch( capsules, h.capsuleID );
	if( e == NULL ) return;
	
	decryptData( &h.encHeader, &h.encHeader, sizeof( encryptedReqHeader ), e );
	memcpy( dHash, h.encHeader.hash, sizeof(dHash) );
	memset( h.encHeader.hash, 0, sizeof(h.encHeader.hash) );
	hashData( (void*) &h, sizeof( h ), hHash, sizeof(hHash) );
	if( compareHash( hHash, dHash, sizeof(hHash) ) == false ) {
		return;
	}

	switch( h.encHeader.req ) {
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
