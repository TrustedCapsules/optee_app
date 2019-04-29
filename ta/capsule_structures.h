#ifndef STRUCTURE_H
#define STRUCTURE_H

#include <stddef.h>

struct capsule_text {
    int                 ref_count;              // Number of times the capsule has been opened

    struct TrustedCap   header;                 // Trusted capsule header

    unsigned char*      policy_buf;             // Contains the capsule policy (fixed maximum size)
    size_t              policy_len;             // Actual length of policy_buf

    unsigned char*      log_buf;                // Contains the log (fixed maximum size)
    size_t              log_len;                // Actual length of log_buf

    struct kv_pair*     kv_store;               // Contains the capsule specific key-value store
                                                //  (variable maximum size)
    size_t              kv_store_len;           // Number of KV pairs in Store.
    
    unsigned char*      data_buf;               // Contains the capsule data (entire contents)
                                                //  (variable maximum size)
    size_t              data_len;               // Actual length of data_buf

    unsigned char*      data_shadow_buf;        // Contains the capsule data sent back to FUSE
                                                // (entire contents) (variable maximum size)
    size_t              data_shadow_len;        // Actual length of data_shadow_buf

    bool                is_read_only;           //Set when the redact policy is run. 

    struct kv_pair*     secure_storage_bl;      //Blacklist KV store for secure storage
    size_t              secure_storage_bl_len;  //secure storage Blacklist KV length

    struct kv_pair      *metadata_bl;           //Blacklist KV store for capsule metadata
    size_t              metadata_bl_len;        //capsule metadata Blacklist KV length

//TODO: Why is this needed?
    // struct kv_pair      *ta_bl;                 //Blacklist KV store for TA
    // size_t              ta_bl_len;              //TA Blacklist KV length
};


#endif /*STRUCTURE_H*/
