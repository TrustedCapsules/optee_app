#ifndef LINKED_LIST_H
#define LINKED_LIST_H

capsuleTable* newCapsuleTable( size_t sz );
capsuleEntry* newCapsuleEntry( uint32_t capsuleID, const char* name, size_t len );
void          capsuleInsert( capsuleTable *t, capsuleEntry *e );
capsuleEntry* capsuleSearch( capsuleTable *t, msgReqHeader *h );

#endif
