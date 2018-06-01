#ifndef CAPSULE_BENCHMARK_H
#define CAPSULE_BENCHMARK_H

typedef struct benchmarking_ta {
    unsigned long long  encryption;
    unsigned long long  hashing;
    unsigned long long  secure_storage;
    unsigned long long  rpc_calls;
    unsigned long long  policy_eval;
} benchmarking_ta;

#endif
