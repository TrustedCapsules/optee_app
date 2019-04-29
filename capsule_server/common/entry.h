#ifndef ENTRY_H
#define ENTRY_H

typedef struct stateEntry {
	char  				key[128];
	char  				value[128];
	struct stateEntry* 	next;
} stateEntry;

typedef struct stateTable {
	size_t		 size;
	stateEntry*  data[0];
} stateTable;

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

uint32_t 	littleEndianToUint( const unsigned char *id );

#endif
