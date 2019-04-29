#ifndef CAPSULE_H
#define CAPSULE_H

#include <inttypes.h>

// common start
#define CAPSULE_UUID { 0xffa39702, 0x9ce0, 0x47e0, \
    { 0xa1, 0xcb, 0x40, 0x48, 0xcf, 0xdb, 0x84, 0x7d} }
#define UNUSED(x) (void)(x) 
#define HASH_LEN    32              // Used in all hashing functions
// common end

#define BLOCK_LEN 1024

// Replaced by policy start
#define BUFFER_SIZE 1024            // Used here
#define POLICY_SIZE BUFFER_SIZE     // Used by check policy changed lua call
#define PACKET_SIZE BUFFER_SIZE/2   // Used by capsule server
#define HEADER_SIZE 128             // Used by capsule network functions
#define STATE_SIZE  128             // Used for getting and setting state

#define MAX_NUM_KEYS    10          // Maximum number of keys in the capsule key value store
// replaced by policy end

// TODO: add to common DONE
#define SHARED_MEM_SIZE BUFFER_SIZE*10 // Used in tests - 10 KB buffer size

// common start
#define DELIMITER "\n----\n"
#define DELIMITER_SIZE 6
#define TRUSTEDCAP "TRUSTEDCAP"
// common end

// TODO: add to common DONE
#define CHECK_SUCCESS(res, ...) if( (res) != TEE_SUCCESS ) { \
                                    MSG( __VA_ARGS__ );      \
                                    return res;              \
                                }

#define CHECK_GOTO(res, go, ...) if( (res) != TEE_SUCCESS ) { \
                                    MSG( __VA_ARGS__ );       \
                                    goto go;                  \
                                 }

// TODO: add to common DONE
struct kv_pair {
    uint32_t key_len;
    uint32_t val_len;
    char* key;
    char* value;
};

// common (changed to trustedCap)
struct TrustedCap {
    char          pad[11];      // bytes 0 - 11 
    unsigned int  capsize;      // bytes 12 - 15 
    unsigned char aes_id[4];    // bytes 16 - 19 
    unsigned char hash[32];     // bytes 20 - 52 
};
// common end

// policy start
typedef enum {
    OPEN_OP,
    CLOSE_OP,
} SYSCALL_OP;
// policy end

// Replaced by server?
typedef enum {
    REQ_TEST,
    RESP_TEST,
    REQ_STATE,
    RESP_STATE,
    REQ_DELETE,
    RESP_DELETE,
    REQ_POLICY_CHANGE,
    RESP_POLICY_CHANGE,
    REQ_SEND_INFO,
    RESP_SEND_ACK,
} SERVER_OP;
// Replaced by server end

// TODO: add to common DONE
// InvokeCommand Operation IDs
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

// TODO: add to common DONE
typedef enum {
    POLICY,
    KV_STRING,
    LOG,
    DATA,
    DATA_SHADOW,
} BUF_TYPE;

// TODO: add to benchmark DONE
struct benchmarking_ta {
    unsigned long long  encryption;
    unsigned long long  hashing;
    unsigned long long  secure_storage;
    unsigned long long  rpc_calls;
    unsigned long long  policy_eval;
};

#endif /* CAPSULE_H */
