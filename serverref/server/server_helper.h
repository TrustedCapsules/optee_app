#ifndef SERVER_HELPER_H
#define SERVER_HELPER_H

// capsuleState stores key/value mappings for a capsule
typedef struct capsuleState {
	unsigned const char *key;
	uint32_t             keyLen;
	unsigned const char *value;
	uint32_t			 value;
} capsuleState;

// capsuleEntry stores info about each capsule that this server 
// serves
typedef struct capsuleEntry {
	unsigned const char *key;
	uint32_t	   	     keyLen;
	uint8_t 	  		*iv;
	uint32_t	   		 iv_len;
	uint32_t 	   		 capsuleID;
	uint32_t       		 policyVersion;
	capsuleState
} capsuleEntry



void register_capsule_entry(void);
void register_state(void);

#endif
