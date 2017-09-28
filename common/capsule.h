#ifndef CAPSULE_H
#define CAPSULE_H

#define CAPSULE_UUID { 0xffa39702, 0x9ce0, 0x47e0, \
	{ 0xa1, 0xcb, 0x40, 0x48, 0xcf, 0xdb, 0x84, 0x7d} }

#define UNUSED(x) (void)(x) 

#define HASH_LEN    32
#define BLOCK_LEN  	1024 

#define BUFFER_SIZE 1024
#define POLICY_SIZE BUFFER_SIZE
#define DATA_SIZE   BUFFER_SIZE
#define PACKET_SIZE BUFFER_SIZE/2
#define HEADER_SIZE 128 
#define STATE_SIZE  128

#define SHARED_MEM_SIZE BUFFER_SIZE

#define DELIMITER "\n----\n"
#define DELIMITER_SIZE 6

#define TRUSTEDCAP "TRUSTEDCAP"

#define CHECK_SUCCESS(res, ...) if( (res) != TEE_SUCCESS ) { \
		 							MSG( __VA_ARGS__ );      \
									return res; 		     \
								}

#define CHECK_GOTO(res, go, ...) if( (res) != TEE_SUCCESS ) { \
									MSG( __VA_ARGS__ );       \
		                            goto go;				  \
								 }

typedef enum {
	START,
	CUR,
	END
} FILE_POS;	

struct TrustedCap {
	char 		  pad[11];
	unsigned int  capsize;
	unsigned char aes_id[4];
	unsigned char hash[32];
};

typedef enum {
	OPEN_OP,
	READ_OP,
	WRITE_OP,
	DECLASSIFY_OP,
	CLOSE_OP,
} SYSCALL_OP;

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

// InvokeCommand Operation IDs
enum command {
	CAPSULE_REGISTER_RSA_KEY,
	CAPSULE_RSA_DECRYPT,
	CAPSULE_RSA_ENCRYPT,
	CAPSULE_REGISTER_AES_KEY,
	CAPSULE_SET_STATE,
	CAPSULE_GET_STATE,
	CAPSULE_CREATE,
	CAPSULE_OPEN,
	CAPSULE_READ,
	CAPSULE_PREAD,
	CAPSULE_CHANGE_POLICY,
	CAPSULE_LSEEK,
	CAPSULE_WRITE,
	CAPSULE_WRITE_EVALUATE,
	CAPSULE_CLOSE,
	CAPSULE_FTRUNCATE,
	CAPSULE_FSTAT,
	CAPSULE_OPEN_CONNECTION,
	CAPSULE_CLOSE_CONNECTION,
	CAPSULE_RECV_CONNECTION,
	CAPSULE_SEND_CONNECTION,
	CAPSULE_SEND,
	CAPSULE_RECV_HEADER,
	CAPSULE_RECV_PAYLOAD,
	CAPSULE_CLEAR_BENCHMARK,
	CAPSULE_COLLECT_BENCHMARK,
};

struct benchmarking_ta {
	unsigned long long 	encryption;
	unsigned long long  hashing;
	unsigned long long  secure_storage;
	unsigned long long  rpc_calls;
	unsigned long long  policy_eval;
};

struct benchmarking_supp {
	unsigned int        action;
	unsigned long long  network;
};

struct benchmarking_driver {
	unsigned long long  module_op;
	unsigned long long  rpc_peripheral_count;
	unsigned long long  rpc_shm_count;
	unsigned long long  rpc_cmd_count;
	unsigned long long  rpc_fs_count;
	unsigned long long  rpc_net_count;
	unsigned long long  rpc_other_count; /*ta, irq, suspend, wait_queue*/
};

struct supp_buf {
	long mytype;
	struct benchmarking_supp info;
};

#endif /* CAPSULE_H */
