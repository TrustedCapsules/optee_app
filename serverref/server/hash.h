#ifndef HASH_H
#define HASH_H

// capsuleState stores key/value mappings for a capsule
typedef struct stateEntry {
	const char  key[128];
	const char  value[128];
} stateEntry;

typedef struct stateTable {
	size_t		 size;
	capsuleState state[0];
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
	stateTable*          stateMap;
	capsuleEntry*        next;
} capsuleEntry

typedef struct capsuleTable {
	size_t       size;
	capsuleEntry data[0];
} capsuleTable;

hashTable* newHashTable( size_t sz );

#endif
