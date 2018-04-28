#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

// TODO: remove dependency once common is re-written
#include <capsule_util.h>

#include "fakeoptee.h"
#include "hash.h"
#include "linkedlist.h"
#include "server_helper.h"

capsuleTable* newCapsuleTable( size_t sz ) {
	capsuleTable *c = (struct capsuleTable*) malloc( sizeof(capsuleTable) ) ;
	c->size = 0; 
	c->head = NULL;
	c->end = NULL;
	return c;
}

capsuleEntry* newCapsuleEntry( uint32_t capsuleID, const char* name, size_t len ) {
	capsuleEntry* c = (capsuleEntry*) malloc( sizeof(capsuleEntry) );

	// For now, all our capsules use the same key/iv for implementation
	// simplicity
	c->key = keyDefault;
	c->keyLen = sizeof( keyDefault );
	c->iv = ivDefault;
	c->ivLen = sizeof( ivDefault );

	c->capsuleID = capsuleID;

	memcpy( c->name, name, len );

	// policyVersion is set to 1 for all capsules for implementation 
	// simplicity
	int v = policyVersion( name );
	if( v == -1 ) {
		printf( "newCapsuleEntry() %s (%u) have unknown policy version\n", 
		name, capsuleID );
		c->policyVersion = 0;
	} else {
		c->policyVersion = (uint32_t) v;
	}
	
	// create 10 state slots for each capsule
	c->stateMap = newStateTable( 10 );
	pthread_mutex_init( &c->stateMapMutex, NULL ); 
	
	c->next = NULL;
	return c;
}

capsuleEntry* capsuleSearch( capsuleTable* t, msgReqHeader* h ) {
	capsuleEntry* e = t->head;
	msgReqHeader dh;

	while( e != NULL ) {
		decryptData( (void*) h, (void*) &dh, sizeof(dh), e );    
		if( e->capsuleID == dh.capsuleID ) { 
			*h = dh;
			return e;
		}
		e = e->next;
	}	

	return NULL;
}

void capsuleInsert( capsuleTable* t, capsuleEntry* e ) {
	
	capsuleEntry* c = t->head;
	if( c == NULL ) {
		t->head = e;
		t->end = e;
		t->size = 1;
		return;
	}

	t->end->next = e;
	t->size += 1;
	return;
}

// capsuleEntry* delete( capsuleTable *t, uint32_t key )
// no need to support right now
