#ifndef FAKEOPTEE_H
#define FAKEOPTEE_H

#define TRUSTEDCAP 			"TRUSTEDCAP"

#define DELIMITER			"\n----\n"
#define DELIMITER_SIZE		6
#define HASHLEN             32
#define POLICY_MAX_SIZE 	2048
#define DEVICE_ID_LEN 		32

typedef enum {
	false,
	true,
} bool;

typedef unsigned int 		uint32_t;
typedef unsigned short		uint16_t;
typedef unsigned char  		uint8_t;

static unsigned char keyDefault[] = { 0x00, 0x01, 0x02, 0x03, 
							  		  0x04, 0x05, 0x06, 0x07, 
								   	  0x08, 0x09, 0x0A, 0x0B, 
								   	  0x0C, 0x0D, 0x0E, 0x0F };

static unsigned char ivDefault[16] = { 0x00 };

typedef struct capsuleManifestEntry {
	const char			        name[45];
	unsigned const char           id[4];
} capsuleManifestEntry;

/* capsule name, capsule ID, device ID */
static capsuleManifestEntry manifest[] = {
 { "bio", { 0x12,0x31,0x2b,0xf1 } },
};

typedef struct trustedCap {
	char			pad[11];		// bytes 0-11
	unsigned int	capsize;		// bytes 12-15
	unsigned char	aes_id[4];		// bytes 16-19
	unsigned char	hash[HASHLEN];	// bytes 20-52
} trustedCap;

#endif
