#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TODO: remove dependency once common is re-written
#include <capsule_util.h>

#include "fakeoptee.h"
#include "hash.h"
#include "linkedlist.h"
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
	memset( s->key, 0, sizeof(s->key) );
	memset( s->value, 0, sizeof(s->value) );
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

  	h = 1; //seed

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

bool keycmp( char *key1, char *key2, size_t len ) {
	for( int i = 0; i < len; i++ ) {
		if( key1[i] != key2[i] ) return false;
	}
	return true;
}

void stateInsert( stateTable* st, char* key, size_t len, stateEntry* e ) {
	uint32_t pos = stateHash( st, key, len );	

	stateEntry* s = st->data[ pos ];
	if( s == NULL ) {
		st->data[pos] = e;
		return;
	}	

	while( s->next != NULL ) {
		// check if the state already exists
		if( keycmp( key, s->key, len ) == true ) {
			memcpy( s->value, e->value, sizeof(s->value) );		
			free( e );
			return;
		}
		s = s->next;
	}	
	
	s->next = e;	
}

stateEntry* stateSearch( stateTable* st, char* key, size_t len ) {
	uint32_t pos = stateHash( st, key, len );
	
	stateEntry* s = st->data[ pos ];
	
	do {
		if( keycmp( key, s->key, len ) == 0 ) {
			return s;
		}
		s = s->next;
	} while( s != NULL );

	return NULL;
}

// capsuleEntry* delete( capsuleTable *t, uint32_t key )
// no need to support right now
