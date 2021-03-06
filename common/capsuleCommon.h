#ifndef CAPSULE_COMMON_H
#define CAPSULE_COMMON_H

#define CAPSULE_UUID { 0xffa39702, 0x9ce0, 0x47e0, \
    { 0xa1, 0xcb, 0x40, 0x48, 0xcf, 0xdb, 0x84, 0x7d} }

#define UNUSED(x) (void)(x) 

#define TRUSTEDCAP      "TRUSTEDCAP"
#define DELIMITER       "\n----\n"
#define DELIMITER_SIZE  6
#define HASHLEN         32
#define UUIDLEN         32
#define SHARED_MEM_SIZE 1024*10         // Used in tests
#define HEADER_SIZE 128 // Backward compatability with send functions
#define MAX_NUM_KEYS 10 // Maximum number of keys in capsule KV store

#define STATE_SIZE 128 // For backward compatability with tests should be unnecessary when they are rewritten
#include "uthash.h"
// From capsule_gen/src/capsule_util.h
/*
typedef enum {
	false,
	true,
} bool;
*/

// Used all over the place, but mostly in testing?
#define CHECK_SUCCESS(res, ...) if( (res) != TEE_SUCCESS ) { \
                                    MSG( __VA_ARGS__ );      \
                                    return res;              \
                                }

#define CHECK_GOTO(res, go, ...) if( (res) != TEE_SUCCESS ) { \
                                    MSG( __VA_ARGS__ );       \
                                    goto go;                  \
                                 }
// Used to represent KV internally
typedef struct kv_pair {
    uint32_t key_len;
    uint32_t val_len;
    char* key;
    char* value;
    UT_hash_handle hh;
} kv_pair;

// Used by InvokeCommand
enum command {
    CAPSULE_REGISTER_AES_KEY,
    CAPSULE_SET_STATE,
    CAPSULE_GET_STATE,
    CAPSULE_GET_BUFFER,
    CAPSULE_OPEN,
    CAPSULE_CLOSE,
    CAPSULE_OPEN_CONNECTION,
    CAPSULE_CLOSE_CONNECTION,
    CAPSULE_RECV_CONNECTION,
    CAPSULE_SEND_CONNECTION,
    CAPSULE_SEND,
    CAPSULE_RECV_HEADER,
    CAPSULE_RECV_PAYLOAD,
};

// Used for testing
typedef enum {
    POLICY,
    KV_STRING,
    LOG,
    DATA,
    DATA_SHADOW,
} BUF_TYPE;

typedef struct TrustedCap {
	char            pad[11];        // bytes 0-11
	char            uuid[UUIDLEN];  // bytes 12-43
	unsigned int    capsize;        // bytes 44-47
	unsigned char   aes_id[4];      // bytes 48-51
	unsigned char   hash[HASHLEN];  // bytes 52-83
} TrustedCap;

#endif
