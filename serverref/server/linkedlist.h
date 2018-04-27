#ifndef LINKED_LIST_H
#define LINKED_LIST_H

// capsuleEntry stores info about each capsule that this server 
// serves
typedef struct capsuleEntry {
	char				 name[45];
	unsigned char 		*key;
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
	capsuleEntry* head;
	capsuleEntry* end;
} capsuleTable;

capsuleTable* newCapsuleTable( size_t sz );
capsuleEntry* newCapsuleEntry( uint32_t capsuleID, const char* name, size_t len );
void          capsuleInsert( capsuleTable *t, capsuleEntry *e );
capsuleEntry* capsuleSearch( capsuleTable *t, msgReqHeader *h );

#endif
