#ifndef GEN_HELPER_H
#define GEN_HELPER_H

typedef struct capsuleEntry {
	char			name[45];
	unsigned char*	aesKey;
	size_t			aesKeyLength;
	unsigned char*	iv;
	size_t			ivLength;
	unsigned char	id[4];
} capsuleEntry;

typedef enum {
	ALL_SECTION,
	HEADER_SECTION,
	POLICY_SECTION,
	KV_SECTION,
	LOG_SECTION,
	DATA_SECTION,
} SECTION;

typedef struct range {
	size_t start;
	size_t end;
} range;

void encodeToCapsule( char* capsuleName, char* path, char* opath );
void decodeFromCapsule( char *capsuleName, char* path, SECTION s );

#endif
