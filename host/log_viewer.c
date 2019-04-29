//
// Created by eric on 05/02/19.
//
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include "tee_client_api.h"
#include "capsuleCommon.h"
#include "capsule_command.h"

TEEC_Result openLog(char *capsule_path) {
    TEEC_Result res = TEEC_SUCCESS;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID uuid = CAPSULE_UUID;
    FILE *fp = NULL;
    char *encrypted_data, *read_data, *write_data;
    uint32_t read_len = 0, write_len = SHARED_MEM_SIZE;

    // Need 4096 for test capsule_path (489 bytes large encrypted, w/o log expansion)
    if (SHARED_MEM_SIZE < 500) {
        return TEEC_ERROR_GENERIC;
    }

    TEEC_SharedMemory in_mem = {.size = SHARED_MEM_SIZE, .flags = TEEC_MEM_INPUT,};
    TEEC_SharedMemory inout_mem = {.size = SHARED_MEM_SIZE, .flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT,};
    TEEC_SharedMemory out_mem = {.size = SHARED_MEM_SIZE, .flags = TEEC_MEM_OUTPUT,};

    read_data = malloc(SHARED_MEM_SIZE);
    write_data = malloc(SHARED_MEM_SIZE);

    res = initializeContext(&ctx);
    res = allocateSharedMem(&ctx, &in_mem);
    res = allocateSharedMem(&ctx, &out_mem);
    res = allocateSharedMem(&ctx, &inout_mem);
    res = openSession(&ctx, &sess, &uuid);

    // Read in the capsule_path contents
    fp = fopen(capsule_path, "rb");
    fseek(fp, 0, SEEK_END);
    int encrypt_len = (size_t) ftell(fp); //handle -1 case
    fseek(fp, 0, SEEK_SET);

    encrypted_data = malloc(encrypt_len + 1);
    fread(encrypted_data, encrypt_len, 1, fp);
    encrypted_data[encrypt_len] = '\0';
    fclose(fp);

    res = capsule_open(&sess, &in_mem, &inout_mem, capsule_path, sizeof(capsule_path),
                       encrypted_data, encrypt_len, read_data, &read_len);

//    printf("encdata: %s\n",encrypted_data);
//    printf("unencdata: %s\n",read_data);

    char *buf = malloc(SHARED_MEM_SIZE);
    int buf_len = SHARED_MEM_SIZE;
    // Get log buffer
    res = capsule_get_buffer(&sess, &out_mem, &buf_len, buf, LOG);
    printf("clearing! buffers :)\n\n\n\n");

    printf("log bef: %s\n", buf);

    printf("log after: %s\n", buf);

    res = capsule_close(&sess, false, read_data, read_len, &in_mem,
                        &out_mem, &write_len, write_data);

    res = closeSession(&sess);
    res = freeSharedMem(&in_mem);
    res = freeSharedMem(&inout_mem);
    res = freeSharedMem(&out_mem);
    res = finalizeContext(&ctx);

    free(read_data);
    free(write_data);
    printf("end\n");
    return res;
}

void displayReference(char *path) {
    FILE *fp = fopen(path, "rb");
    fseek(fp, 0, SEEK_END);
    long log_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *log_copy = malloc(log_len + 1);
    fread(log_copy, log_len, 1, fp);
    fclose(fp);
    log_copy[log_len] = '\0';
}

//usage: log_viewer CAPSULE_FILE
int main(int argc, char **argv) {
//    displayReference("/etc/new_capsules/bio.log");
    if (argc == 1) {
        TEEC_Result res = openLog("/etc/new_capsules/bio.capsule");
    } else {
        TEEC_Result res = openLog(argv[1]);
    }
}