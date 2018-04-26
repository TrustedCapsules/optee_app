#ifndef HASH_H
#define HASH_H

// capsuleState stores key/value mappings for a capsule
typedef struct stateEntry {
	char  				key[128];
	char  				value[128];
	struct stateEntry* 	next;
} stateEntry;

typedef struct stateTable {
	size_t		 size;
	stateEntry*  data[0];
} stateTable;


// capsuleEntry stores info about each capsule that this server 
// serves
typedef struct capsuleEntry {
	char				 name[45];
	unsigned const char *key;
	uint32_t	   	     keyLen;
	uint8_t 	  		*iv;
	uint32_t	   		 ivLen;
	uint32_t 	   		 capsuleID;
	uint32_t       		 policyVersion;
	pthread_mutex_t      stateMapMutex;
	stateTable*          stateMap;
	struct capsuleEntry* next;
} capsuleEntry;

typedef struct capsuleTable {
	size_t        size;
	capsuleEntry* data[0];
} capsuleTable;


stateTable* newStateTable( size_t sz );
stateEntry* newStateEntry( const char* key, size_t keyLen,
						   const char* val, size_t valLen );
uint32_t    stateHash( stateTable *t, const char* key, size_t len );
void 		stateInsert( stateTable *st, char* key, size_t len, stateEntry *e );
stateEntry* stateSearch( stateTable *st, char* key, size_t len );

capsuleTable* newCapsuleTable( size_t sz );
capsuleEntry* newCapsuleEntry( uint32_t capsuleID, const char* name, size_t len );
uint32_t 	  capsuleHash( capsuleTable *t, uint32_t key );
void          capsuleInsert( capsuleTable *t, uint32_t key, capsuleEntry *e );
capsuleEntry* capsuleSearch( capsuleTable *t, uint32_t key );

#endif
