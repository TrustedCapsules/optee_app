#ifndef TEST_PERFORMANCE_H
#define TEST_PERFORMANCE_H

int load_system(void);
int test_read_throughput(char* file_name, int num_secs, int total_run_time);
int test_write_throughput(char* file_name, int num_secs, int total_run_time);
int test_op_latency(char* file_name, int iterations, int num_bytes, char* op);
int test_tainted_process(char* file_name, int num_capsules, int num_secs);

#endif
