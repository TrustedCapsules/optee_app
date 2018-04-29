#ifndef HASH_H
#define HASH_H

stateTable* newStateTable( size_t sz );
stateEntry* newStateEntry( const char* key, size_t keyLen,
						   const char* val, size_t valLen );
uint32_t    stateHash( stateTable *t, const char* key, size_t len );
void 		stateInsert( stateTable *st, stateEntry *e, size_t len );
stateEntry* stateSearch( stateTable *st, char* key, size_t len );

#endif
