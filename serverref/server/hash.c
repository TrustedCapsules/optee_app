#include <stdio.h>
#include <stdlib.h>

#include "fakekeys.h"
#include "hash.h"
#include "server_helper.h"

stateTable* newStateTable( size_t sz ) {
	stateTable *s = (struct stateTable*) malloc( sizeof(stateTable) + 
												sz * sizeof(stateEntry*) );
	s->size = sz; 
	for( size_t i = 0; i < sz; i++ ) {
		s->data[i] = NULL;
	}
	return s;
}

stateEntry* newStateEntry( const char* key, size_t keyLen, 
						   const char* val, size_t valLen ) {
	stateEntry* s = (struct stateEntry*) malloc( sizeof(stateEntry) );

	// We assume that key/val length are less than the statically sized
	// key/value members of stateEntry. Because writing boundary checks
	// is annoying and I have to meet a friend.
	memcpy( s->key, key, keyLen );
	memcpy( s->value, val, valLen );

	return s;
}

// Murmur hash
uint32_t stateHash( stateTable* t, const char* key, size_t len ) {
	uint32_t c1 = 0xcc9e2d51;
  	uint32_t c2 = 0x1b873593;
  	uint32_t r1 = 15;
  	uint32_t r2 = 13;
  	uint32_t m = 5;
  	uint32_t n = 0xe6546b64;
  	uint32_t h = 0;
  	uint32_t k = 0;
  	uint8_t *d = (uint8_t *) key; // 32 bit extract from `key'
  	const uint32_t *chunks = NULL;
  	const uint8_t *tail = NULL; // tail - last 8 bytes
  	int i = 0;
  	int l = len / 4; // chunk length

  	h = seed;

  	chunks = (const uint32_t *) (d + l * 4); // body
  	tail = (const uint8_t *) (d + l * 4); // last 8 byte chunk of `key'

  	// for each 4 byte chunk of `key'
  	for (i = -l; i != 0; ++i) {
    	// next 4 byte chunk of `key'
    	k = chunks[i];

    	// encode next 4 byte chunk of `key'
    	k *= c1;
    	k = (k << r1) | (k >> (32 - r1));
    	k *= c2;

    	// append to hash
    	h ^= k;
    	h = (h << r2) | (h >> (32 - r2));
    	h = h * m + n;
  	}

  	k = 0;

  	// remainder
  	switch (len & 3) { // `len % 4'
    	case 3: k ^= (tail[2] << 16);
    	case 2: k ^= (tail[1] << 8);
    	case 1:
      		k ^= tail[0];
      		k *= c1;
      		k = (k << r1) | (k >> (32 - r1));
      		k *= c2;
      		h ^= k;
  	}

  	h ^= len;

  	h ^= (h >> 16);
  	h *= 0x85ebca6b;
  	h ^= (h >> 13);
  	h *= 0xc2b2ae35;
  	h ^= (h >> 16);

  	return h % t->size;
}

void stateInsert( stateTable* st, uint32_t key, stateEntry* e ) {
	uint32_t pos = stateHash( key % st.size );
	
	stateEntry* s = st.data[ pos ];
	if( s == NULL ) {
		t.data[pos] = e;
		return;
	}	
	
	while( s->next != NULL ) {
		s = s->next;
	}	
	
	s->next = e;	
}

// capsuleEntry* delete( capsuleTable *t, uint32_t key )
// no need to support right now

stateTable* newCapsuleTable( size_t sz ) {
	capsuleTable *c = (struct capsuleTable*) malloc( sizeof(capsuleTable) + 
												sz * sizeof(capsuleEntry*) );
	c->size = sz; 
	for( size_t i = 0; i < sz; i++ ) {
		c->data[i] = NULL;
	}
	return c;
}

capsuleEntry* newCapsuleEntry( uint32_t capsuleID, const char* name, size_t len ) {
	capsuleEntry* c = (struct capsuleEntry*) malloc( sizeof(capsuleEntry) );

	// For now, all our capsules use the same key/iv for implementation
	// simplicity
	c->key = std_key;
	c->keyLen = sizeof( key_std );
	c->iv = std_iv;
	c->ivLen = sizeof( iv_std );

	c->capsuleID = capsuleID;

	memcpy( c->name, name, len );

	// policyVersion is set to 1 for all capsules for implementation 
	// simplicity
	c->policyVerison = 1;
	
	// create 10 state slots for each capsule
	c->stateMap = newStateTable( 10 );;
	
	c->next = NULL;
	return c;
}

uint32_t capsuleHash( capsuleTable* t, uint32_t key ) {
	return key % t.size;
}

capsuleEntry* capsuleSearch( capsuleTable* t, uint32_t key ) {
	uint32_t pos = hashCode( key % t.size );
	
	capsuleEntry* c = t.data[ pos ];
	
	do {
		if( c->capsuleID == key ) return c;
		c = c->next;
	} while( c != NULL );

	return NULL;
}

void capsuleInsert( capsuleTable* t, uint32_t key, capsuleEntry* e ) {
	uint32_t pos = hashCode( key % t.size );
	
	capsuleEntry* c = t.data[ pos ];
	if( c == NULL ) {
		t.data[pos] = e;
		return;
	}	
	
	while( c->next != NULL ) {
		c = c->next;
	}	
	
	c->next = e;	
}

// capsuleEntry* delete( capsuleTable *t, uint32_t key )
// no need to support right now
