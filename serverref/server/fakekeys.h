#ifndef FAKEKEYS_H
#define FAKEKEYS_H

static unsigned char key_std[] = { 0x00, 0x01, 0x02, 0x03, 
								   0x04, 0x05, 0x06, 0x07, 
								   0x08, 0x09, 0x0A, 0x0B, 
								   0x0C, 0x0D, 0x0E, 0x0F };

static unsigned char iv_std[16] = { 0x00 };

struct capsuleManifestEntry {
	unsigned const char        name[45];
	unsigned const char           id[4];
};

/* capsule name, capsule ID, device ID */
static struct capsuleManifestEntry manifest[] = {
 { "bio", { 0x12,0x31,0x2b,0xf1 } },
};

#endif
