#ifndef STRUCTURE_H
#define STRUCTURE_H

struct kv_pair {
    int key_len;
    int val_len;
    char* key;
    char* value;
};

struct capsule_text {
    int                 ref_count;          // Number of times the capsule has been opened

    struct TrustedCap   header;             // Trusted capsule header

    unsigned char*      policy_buf;         // Contains the capsule policy (fixed maximum size)
    size_t              policy_len;         // Actual length of policy_buf

    unsigned char*      log_buf;            // Contains the log (fixed maximum size)
    size_t              log_len;            // Actual length of log_buf

    struct kv_pair*     kv_store_buf;       // Contains the capsule specific key-value store
                                            //  (variable maximum size)
    size_t              kv_store_len;       // Actual length of kv_store_buf
    
    unsigned char*      data_buf;           // Contains the capsule data (entire contents)
                                            //  (variable maximum size)
    size_t              data_len;           // Actual length of data_buf

    unsigned char*      data_shadow_buf;    // Contains the capsule data sent back to FUSE
                                            // (entire contents) (variable maximum size)
    size_t              data_shadow_len;    // Actual length of data_shadow_buf
};


#endif /*STRUCTURE_H*/
