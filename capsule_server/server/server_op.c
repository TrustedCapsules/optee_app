#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <stdint.h>
#include <tomcrypt.h>

#include <capsuleCommon.h>
#include <capsuleServerProtocol.h>
#include <capsulePolicy.h>
#include <capsuleCrypt.h>

#include "../common/entry.h"
#include "../common/serverTomCrypt.h"
#include "hash.h"
#include "linkedlist.h"
#include "server_helper.h"

extern capsuleTable* capsules;

void printHash( const unsigned char* h, size_t len ) {
	for( int i = 0; i < len; i ++ ) {
		if( i != 0 && i % 4 == 0 ) {
			printf( " " );
		}
		printf( "%02x", h[i] );
	}
}

void printChars( const char* h, size_t len ) {
	for( int i = 0; i < len; i ++ ) {
		printf( "%c", h[i] );
	}
}

void reply( int fd, msgReqHeader *reqHeader, capsuleEntry *e, 
			SERVER_REPLY sr, size_t payloadLen, char* payload ) {
	
	msgReplyHeader replyHeader;
	unsigned char 	hHash[HASHLEN] = {0};
	
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
	unsigned char hash[HASHLEN] = {0};
	size_t 		  payloadLen = sizeof( msgPayload ) + reqHeader->payloadLen;	
	msgPayload *p = ( msgPayload* ) malloc( payloadLen );	
	int nr = recvData( fd, (void*) p, payloadLen );
	if( nr != (int) payloadLen ) {
		printf( "recvPayload(): expected %zu (B) got %d (B)\n", payloadLen, nr );
		free( p );
		return NULL;
	}
	
	decryptData( (void*) p, (void*) p, payloadLen, e );
	hashData( (void*) p->payload, reqHeader->payloadLen, hash, sizeof(hash) );
	if( compareHash( hash, p->hash, sizeof(hash) ) == false ) {
		printf( "recvPayload(): hash does not match\n" );
		free( p );
		return NULL;
	}

	if( reqHeader->nonce != p->nonce ) {
		printf( "recvPayload(): nonce does not match\n" );
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
		printf( "handleGetState(): payload recv() error\n" );
		reply( fd, reqHeader, e, FAILURE, 0, NULL );
		return;
	}

	char *key = (char*) malloc( reqHeader->payloadLen + 1 );
	memset( key, 0, reqHeader->payloadLen + 1 );
	memcpy( key, p->payload, reqHeader->payloadLen );
	free( p );

	pthread_mutex_lock( &e->stateMapMutex );
		
	stateEntry *s = stateSearch( e->stateMap, key, reqHeader->payloadLen );
	pthread_mutex_unlock( &e->stateMapMutex );	
	if( s == NULL ) {
		printf( "handleGetState(): state %s not found\n", key );
		reply( fd, reqHeader, e, FAILURE, 0, NULL );
	}

	reply( fd, reqHeader, e, SUCCESS, strlen( s->value ), s->value ); 
	free( key );
}

void handleGetTime( int fd, msgReqHeader *reqHeader, capsuleEntry *e ){
	time_t rawtime;
	int res = 0;
	char *timeStr;

	res = time(&rawtime);
	if(res < 0){
		printf("handleGetTime(): time could not be retrieved\n");
		reply(fd, reqHeader, e, FAILURE, 0, NULL);
	}
	sprintf(timeStr,"%ld",rawtime);
	reply(fd, reqHeader, e, SUCCESS, strlen(timeStr), timeStr);
}

void handleSetState( int fd, msgReqHeader *reqHeader, capsuleEntry *e ) {
	msgPayload *p = recvPayload( fd, reqHeader, e );
	if( p == NULL ) {
		printf( "handleSetState(): payload recv() error\n" );
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
	printf( "%s\n", p->payload );	
	size_t len = append_file( logFile, p->payload, reqHeader->payloadLen );
	
	reply( fd, reqHeader, e, 
		   len == reqHeader->payloadLen ? SUCCESS : FAILURE, 
		   0, NULL );
	free( p );	
}

void* handleCapsule( void* ptr ) {
	int					fd = *(int*) ptr;
	msgReqHeader 	  	h = {0};
	unsigned char 		hHash[HASHLEN] = {0};
	unsigned char 		dHash[HASHLEN] = {0};

	int nr = recvData( fd, (void*) &h, sizeof(h) );
	if( nr != (int) sizeof(h) ) {
		printf( "handleCapsule(): nr %d != msgReqHeader size %zu\n", nr, sizeof(h) );
		return NULL;
	}

	capsuleEntry *e = capsuleSearch( capsules, &h );
	if( e == NULL ) { 
		printf( "handleCapsule(): no capsule found\n" );
		return NULL;
	}
	
	memcpy( dHash, h.hash, sizeof(h.hash) );
	memset( h.hash, 0, sizeof(h.hash) );
		
	/*	
	printf( "capsuleSearch(): decrypted header\n");
	printf( "\tcapsuleID = 0x%x\n", h.capsuleID );
	printf( "\tdeviceID = " );
	printChars( h.deviceID, DEVICE_ID_LEN );
	printf( "\n" );
	printf( "\treq = %d\n", h.req );
	printf( "\tnonce = %d\n", h.nonce );
	printf( "\thash = " );
	printHash( h.hash, HASHLEN );
	printf( "\n" );
	printf( "\tpayload length= %zu\n", h.payloadLen );
	*/	
	
	hashData( (void*) &h, sizeof( h ), hHash, sizeof(hHash) );
	if( compareHash( hHash, dHash, sizeof(dHash) ) == false ) {
		/*
		printf( "handleCapsule(): header hash does not match\n" );
		printf( "\tExpected - " );
		printHash( dHash, HASHLEN );
		printf( "\n" );
		printf( "\tGot      - " );
		printHash( hHash, HASHLEN );
		printf( "\n" );
		*/
		reply( fd, &h, e, FAILURE, 0, NULL );
		return NULL;
	}

	switch( h.req ) {
		case ECHO:
			printf( "handleCapsule(): handleEcho\n" ); 
			handleEcho( fd, &h, e );
			return NULL;
		case GET_STATE: 
			printf( "handleCapsule(): handleGetState\n" );
			handleGetState( fd, &h, e );
			return NULL;
		case SET_STATE:
			printf( "handleCapsule(): handleSetState\n" ); 
			handleSetState( fd, &h, e );
			return NULL;
		case POLICY_UPDATE: 
			printf( "handleCapsule(): handlePolicyUpdate\n" ); 
			handlePolicyUpdate( fd, &h, e );
			return NULL;
		case LOG_ENTRY: 
			printf( "handleCapsule(): handleLog\n" ); 
			handleLog( fd, &h, e );
			return NULL;
		case GET_TIME:
			printf( "handleCapsule(): handleGetTiem\n" );
			handleGetTime( fd, &h, e );
			return NULL;
		default: 
			 reply( fd, &h, e, FAILURE, 0, NULL );
	}

	return NULL;
}
