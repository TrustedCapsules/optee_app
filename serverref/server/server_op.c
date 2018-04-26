#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "fakeoptee.h"
#include "hash.h"
#include "server_helper.h"

extern capsuleTable* capsules;

void replyError( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
	msgReplyHeader replyHeader;
	unsigned char  hash[HASHLEN];
	
	replyHeader.capsuleID = reqHeader->capsuleID;
	replyHeader.deviceID = reqHeader->deviceID;
	replyHeader.response = FAILURE;
	replyHeader.nonce = nonce;
	replyHeader.payloadLen = 0;
	memset( replyHeader.hash, 0, sizeof(replyHeader.hash) );

	hashData( (void*) &replyHeader, sizeof(replyHeader), hash, sizeof(hash) );
	memcpy( replyHeader.hash, hash, sizeof(hash) );	

	encryptData( (void*) &replyHeader, 
				 (void*) &replyHeader, 
				 sizeof(replyHeader), e );

	sendData( fd, (void*) &replyHeader, sizeof(replyHeader) );
}

void handleEcho( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
}
void handleGetState( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
}
void handleSetState( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
}
void handlePolicyUpdate( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
}
void handleLog( int fd, msgHeader *reqHeader, capsuleEntry *e ) {
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
	
	decryptData( &h.encHeader, &h.encHeader, sizeof( encyptedReqHeader ), e );
	memcpy( dHash, h.encHeader.hash, sizeof(dHash) );
	memset( h.encHeader.hash, 0, sizeof(h.encHeader.hash) );
	hashData( (void*) h, sizeof( h ), hHash, sizeof(hHash) );
	if( compareHash( hHash, dHash ) == false ) {
		return;
	}

	switch( h->req ) {
		case ECHO: return handleEcho( fd, &h, e );
		case GET_STATE: return handleGetState( fd, &h, e );
		case SET_STATE: return handleSetState( fd, &h, e );
		case POLICY_UPDATE: return handlePolicyUpdate( fd, &h, e );
		case LOG: return handleLog( fd, &h );
		case default: 
			 replyError( fd, &h, e );
	}
}
