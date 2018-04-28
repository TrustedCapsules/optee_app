#ifndef CLIENT_HELPER_H
#define CLIENT_HELPER_H

int 		createReqHeader( msgReqHeader *h, capsuleEntry *e, 
							 SERVER_REQ q, int len );
int 		validateAndDecryptReplyHeader( int nonce, msgReplyHeader *r, 
										   capsuleEntry *e );
msgPayload* recvPayload( int nonce, msgReplyHeader *r, capsuleEntry *e );

#endif
