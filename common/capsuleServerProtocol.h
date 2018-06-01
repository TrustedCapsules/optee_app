#ifndef CAPSULE_SERVER_PROTOCOL_H
#define CAPSULE_SERVER_PROTOCOL_H

#define DEVICE_ID_LEN 		32

typedef enum {
	ECHO = 0,
	GET_STATE,
	SET_STATE,
	POLICY_UPDATE,
	LOG_ENTRY,
} SERVER_OP;

typedef enum {
	SUCCESS = 0,
	FAILURE,
} SERVER_REPLY;

typedef struct msgReqHeader {
	uint32_t 				capsuleID;
	char	 				deviceID[DEVICE_ID_LEN];
	int						req;
	int						nonce;
	unsigned char			hash[HASHLEN];
	// ECHO 	 		-   0
	// GET_STATE 		-   length of key
	// SET_STATE 		-   length of key:value
	// POLICY_UPDATE 	- 	length of int version
	// LOG_ENTRY		-   length of []char
	size_t					payloadLen;
} msgReqHeader;

typedef struct msgReplyHeader {
	uint32_t 		capsuleID;
	int				response;
	int				nonce;
	unsigned char	hash[HASHLEN];
	// This is the length of msgPayload->payload
	// ECHO 	 		-   0
	// GET_STATE 		-   len of value
	// SET_STATE 		-   0
	// POLICY_UPDATE 	- 	payloadLen = 0 if no upload OR 
	//                      size of policy file
	// LOG_ENTRY		-  	0
	int				payloadLen;
} msgReplyHeader;

typedef struct msgPayload {
	int 			nonce;
	unsigned char	hash[HASHLEN];
	char			payload[0];
} msgPayload;

#endif
