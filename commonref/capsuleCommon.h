#ifndef CAPSULE_COMMON_H
#define CAPSULE_COMMON_H

#define CAPSULE_UUID { 0xffa39702, 0x9ce0, 0x47e0, \
    { 0xa1, 0xcb, 0x40, 0x48, 0xcf, 0xdb, 0x84, 0x7d} }

#define UNUSED(x) (void)(x) 

#define TRUSTEDCAP 					"TRUSTEDCAP"
#define DELIMITER 					"\n----\n"
#define DELIMITER_SIZE 				6

#define HASHLEN    					32

typedef enum {
	false,
	true,
} bool;

typedef struct trustedCap {
	char			pad[11];		// bytes 0-11
	unsigned int	capsize;		// bytes 12-15
	unsigned char	aes_id[4];		// bytes 16-19
	unsigned char	hash[HASHLEN];	// bytes 20-52
} trustedCap;

#endif
