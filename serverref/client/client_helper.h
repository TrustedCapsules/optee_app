#ifndef CLIENT_HELPER_H
#define CLIENT_HELPER_H

msgPayload* createReqPayload( int nonce, char* str, 
							  size_t strLen, capsuleEntry *e );
int 		createReqHeader( msgReqHeader *h, capsuleEntry *e, 
							 SERVER_REQ q, int len );
int 		validateAndDecryptReplyHeader( int nonce, msgReplyHeader *r, 
										   capsuleEntry *e );
msgPayload* recvPayload( int fd, int nonce, msgReplyHeader *r, capsuleEntry *e );

#endif
