#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <capsule.h>
#include <aes_keys.h>
#include <syslog.h>
#include "err_ta.h"
#include "key_data.h"
#include "capsule_benchmark.h"
#include "capsule_command.h"

/* Test with multiple opens and closes of different no-op capsules.
 */
TEEC_Result test_07() {
    TEEC_Result     res = TEEC_SUCCESS;
    TEEC_Context    ctx;
    TEEC_Session    sess;
    TEEC_Session    sess2;
    TEEC_UUID       uuid = CAPSULE_UUID;
    char            capsule[] = "/etc/use_case_capsules/test_bio_ehrpatient.capsule";
    char            ptx[] = "/etc/use_case_capsules/test_bio_ehrpatient.data";
    char            capsule2[] = "/etc/sample_capsules/short_story.capsule";
    char            ptx2[] = "/etc/sample_capsules/short_story.data";
    FILE           *fp = NULL;
    char           *encrypted_data1, 
                   *encrypted_data2, 
                   *read_data,
                   *write_data,
                   *plain_text_data1,
                   *plain_text_data2;
    uint32_t        encrypt_len1 = 0, 
                    encrypt_len2 = 0, 
                    read_len = 0, 
                    write_len = 10000, // Short story is 8547
                    plt_len1 = 0,
                    plt_len2 = 0;
    int             i = 0, 
                    test_num = 7;

    PRINT_INFO("test_%02d: multiple capsules (open/close)\n",
                test_num);

    // Need 4096 for test capsule (489 bytes large encrypted, w/o log expansion)
    if (SHARED_MEM_SIZE < 500) {
        res = TEEC_ERROR_GENERIC;
        CHECK_RESULT( res, "test_%02d: SHARED_MEM_SIZE must be greater than 500"
                           " for this test to run. It is %d", test_num, 
                           SHARED_MEM_SIZE);
    }

    TEEC_SharedMemory in_mem = { .size = 10000,
                                 .flags = TEEC_MEM_INPUT, };
    TEEC_SharedMemory inout_mem = { .size = 10000,
                                    .flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT, };
    TEEC_SharedMemory out_mem = { .size = 10000,
                                  .flags = TEEC_MEM_OUTPUT, };

    read_data = malloc(10000);
    write_data = malloc(10000);

    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "test_%02d: initializeContext() failed", test_num );

    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() in_mem failed", 
                       test_num);
    res = allocateSharedMem( &ctx, &out_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() out_mem failed",
                       test_num);
    res = allocateSharedMem( &ctx, &inout_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() inout_mem failed",
                       test_num);

    res = openSession( &ctx, &sess, &uuid );
    CHECK_RESULT( res, "test_%02d: openSession() sess failed", test_num );

    res = openSession( &ctx, &sess2, &uuid );
    CHECK_RESULT( res, "test_%02d: openSession() sess2 failed", test_num );

    // Read in the capsule contents
    fp = fopen(capsule, "rb");
    fseek(fp, 0, SEEK_END);
    encrypt_len1 = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    encrypted_data1 = malloc(encrypt_len1 + 1);
    fread(encrypted_data1, encrypt_len1, 1, fp);
    fclose(fp);

    encrypted_data1[encrypt_len1] = '\0';

    // Read in data contents
    fp = fopen(ptx, "rb");
    fseek(fp, 0, SEEK_END);
    plt_len1 = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    plain_text_data1 = malloc(plt_len1 + 1);
    fread(plain_text_data1, plt_len1, 1, fp);
    fclose(fp);

    plain_text_data1[plt_len1] = '\0';

    // Read in the capsule contents
    fp = fopen(capsule2, "rb");
    fseek(fp, 0, SEEK_END);
    encrypt_len2 = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    encrypted_data2 = malloc(encrypt_len2 + 1);
    fread(encrypted_data2, encrypt_len2, 1, fp);
    fclose(fp);

    encrypted_data2[encrypt_len2] = '\0';

    // Read in data contents
    fp = fopen(ptx2, "rb");
    fseek(fp, 0, SEEK_END);
    plt_len2 = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    plain_text_data2 = malloc(plt_len2 + 1);
    fread(plain_text_data2, plt_len2, 1, fp);
    fclose(fp);

    plain_text_data2[plt_len2] = '\0';

    // First read
    res = capsule_open( &sess, &in_mem, &inout_mem, capsule, sizeof(capsule),
                        encrypted_data1, encrypt_len1, read_data, &read_len );
    CHECK_RESULT( res, "test_%02d: first capsule_open() of capsule %s failed", 
                        test_num, capsule );

    // Compare decrypted data with plaintext data
    COMPARE_LEN( test_num, 1, read_len, plt_len1 );
    COMPARE_TEXT( test_num, 1, i, read_data, plain_text_data1, read_len );

    // First close
    res = capsule_close( &sess, false, read_data, read_len, &in_mem,
                         &out_mem, &write_len, write_data );
    CHECK_RESULT( res, "test_%02d: first capsule_close() %s failed", test_num,
                  capsule );

    // Compare write data with encrypted data. 
    COMPARE_LEN( test_num, 2, write_len, encrypt_len1 );
    COMPARE_CAPSULE( test_num, 2, i, encrypted_data1, write_data, write_len );

    // Second read
    // NOTE: cannot memset for SHARED_MEM_SIZE b/c capsule_open realloc'd the
    // memory to fit the particular size sent back (read_len)
    memset(read_data, 0, read_len);
    read_len = 0;

    res = capsule_open( &sess2, &in_mem, &inout_mem, capsule2, sizeof(capsule2),
                        encrypted_data2, encrypt_len2, read_data, &read_len );
    CHECK_RESULT( res, "test_%02d: second capsule_open() of capsule %s failed", 
                        test_num, capsule2 );

    // Compare decrypted data with plaintext data
    COMPARE_LEN( test_num, 1, read_len, plt_len2 );
    COMPARE_TEXT( test_num, 1, i, read_data, plain_text_data2, read_len );

    // Second close
    memset(write_data, 0, write_len);
    write_len = 10000;

    res = capsule_close( &sess2, false, read_data, read_len, &in_mem,
                         &out_mem, &write_len, write_data );
    CHECK_RESULT( res, "test_%02d: second capsule_close() %s failed", test_num,
                  capsule2 );

    // Compare write data with encrypted data. 
    COMPARE_LEN( test_num, 2, write_len, encrypt_len2 );
    COMPARE_CAPSULE( test_num, 2, i, encrypted_data2, write_data, write_len );

    res = closeSession( &sess );
    CHECK_RESULT( res, "test_%02d: closeSession() sess failed", test_num );

    res = closeSession( &sess2 );
    CHECK_RESULT( res, "test_%02d: closeSession() sess2 failed", test_num );

    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() in_mem failed", test_num );

    res = freeSharedMem( &inout_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() inout_mem failed", test_num );

    res = freeSharedMem( &out_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() out_mem failed", test_num );
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "test_%02d: finalizeContext() failed", test_num );

    return res;
}

/* Test no-op capsule with two closes.
 * 
 * Expected result: second close fails
 */
TEEC_Result test_06() {
    TEEC_Result     res = TEEC_SUCCESS;
    TEEC_Context    ctx;
    TEEC_Session    sess;
    TEEC_UUID       uuid = CAPSULE_UUID;
    char            capsule[] = "/etc/use_case_capsules/test_bio_ehrpatient.capsule";
    char            ptx[] = "/etc/use_case_capsules/test_bio_ehrpatient.data";
    FILE           *fp = NULL;
    char           *encrypted_data, 
                   *read_data,
                   *write_data,
                   *plain_text_data;
    uint32_t        encrypt_len = 0, 
                    read_len = 0, 
                    write_len = SHARED_MEM_SIZE,
                    plt_len = 0;
    int             i = 0, 
                    test_num = 6;

    PRINT_INFO("test_%02d: close capsule after closing\n",
                test_num);

    // Need 4096 for test capsule (489 bytes large encrypted, w/o log expansion)
    if (SHARED_MEM_SIZE < 500) {
        res = TEEC_ERROR_GENERIC;
        CHECK_RESULT( res, "test_%02d: SHARED_MEM_SIZE must be greater than 500"
                           " for this test to run. It is %d", test_num, 
                           SHARED_MEM_SIZE);
    }

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    TEEC_SharedMemory inout_mem = { .size = SHARED_MEM_SIZE,
                                    .flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT, };
    TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
                                  .flags = TEEC_MEM_OUTPUT, };

    read_data = malloc(SHARED_MEM_SIZE);
    write_data = malloc(SHARED_MEM_SIZE);

    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "test_%02d: initializeContext() failed", test_num );

    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() in_mem failed", 
                       test_num);
    res = allocateSharedMem( &ctx, &out_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() out_mem failed",
                       test_num);
    res = allocateSharedMem( &ctx, &inout_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() inout_mem failed",
                       test_num);

    res = openSession( &ctx, &sess, &uuid );
    CHECK_RESULT( res, "test_%02d: openSession() sess failed", test_num );

    // Read in the capsule contents
    fp = fopen(capsule, "rb");
    fseek(fp, 0, SEEK_END);
    encrypt_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    encrypted_data = malloc(encrypt_len + 1);
    fread(encrypted_data, encrypt_len, 1, fp);
    fclose(fp);

    encrypted_data[encrypt_len] = '\0';

    // Read in data contents
    fp = fopen(ptx, "rb");
    fseek(fp, 0, SEEK_END);
    plt_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    plain_text_data = malloc(plt_len + 1);
    fread(plain_text_data, plt_len, 1, fp);
    fclose(fp);

    plain_text_data[plt_len] = '\0';

    res = capsule_open( &sess, &in_mem, &inout_mem, capsule, sizeof(capsule),
                        encrypted_data, encrypt_len, read_data, &read_len );
    CHECK_RESULT( res, "test_%02d: capsule_open() of capsule %s failed", 
                        test_num, capsule );

    // Compare decrypted data with plaintext data
    COMPARE_LEN( test_num, 1, read_len, plt_len );
    COMPARE_TEXT( test_num, 1, i, read_data, plain_text_data, read_len );

    res = capsule_close( &sess, false, read_data, read_len, &in_mem,
                         &out_mem, &write_len, write_data );
    CHECK_RESULT( res, "test_%02d: capsule_close() %s failed", test_num,
                  capsule );

    // Compare write data with encrypted data. 
    COMPARE_LEN( test_num, 2, write_len, encrypt_len );
    COMPARE_CAPSULE( test_num, 2, i, encrypted_data, write_data, write_len );

    // Second close -- SHOULD FAIL
    // NOTE: cannot memset for SHARED_MEM_SIZE b/c capsule_open realloc'd the
    // memory to fit the particular size sent back (read_len)
    memset(write_data, 0, write_len);
    write_len = 0;

    res = capsule_close( &sess, false, read_data, read_len, &in_mem,
                         &out_mem, &write_len, write_data );
    if (res == TEEC_SUCCESS) {
        res = TEEC_ERROR_GENERIC;
        CHECK_RESULT( res, "test_%02d: second capsule_close() DID NOT fail after close.", test_num );
    }

    res = closeSession( &sess );
    CHECK_RESULT( res, "test_%02d: closeSession() failed", test_num );

    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() in_mem failed", test_num );

    res = freeSharedMem( &inout_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() inout_mem failed", test_num );

    res = freeSharedMem( &out_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() out_mem failed", test_num );
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "test_%02d: finalizeContext() failed", test_num );

    return res;
}

/* Test no-op capsule with open after close.
 * 
 * Expected result: open succeeds
 */
TEEC_Result test_05() {
    TEEC_Result     res = TEEC_SUCCESS;
    TEEC_Context    ctx;
    TEEC_Session    sess;
    TEEC_UUID       uuid = CAPSULE_UUID;
    char            capsule[] = "/etc/use_case_capsules/test_bio_ehrpatient.capsule";
    char            ptx[] = "/etc/use_case_capsules/test_bio_ehrpatient.data";
    FILE           *fp = NULL;
    char           *encrypted_data, 
                   *read_data,
                   *write_data,
                   *plain_text_data;
    uint32_t        encrypt_len = 0, 
                    read_len = 0, 
                    write_len = SHARED_MEM_SIZE,
                    plt_len = 0;
    int             i = 0, 
                    test_num = 5;

    PRINT_INFO("test_%02d: open capsule after closing\n",
                test_num);

    // Need 4096 for test capsule (489 bytes large encrypted, w/o log expansion)
    if (SHARED_MEM_SIZE < 500) {
        res = TEEC_ERROR_GENERIC;
        CHECK_RESULT( res, "test_%02d: SHARED_MEM_SIZE must be greater than 500"
                           " for this test to run. It is %d", test_num, 
                           SHARED_MEM_SIZE);
    }

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    TEEC_SharedMemory inout_mem = { .size = SHARED_MEM_SIZE,
                                    .flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT, };
    TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
                                  .flags = TEEC_MEM_OUTPUT, };

    read_data = malloc(SHARED_MEM_SIZE);
    write_data = malloc(SHARED_MEM_SIZE);

    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "test_%02d: initializeContext() failed", test_num );

    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() in_mem failed", 
                       test_num);
    res = allocateSharedMem( &ctx, &out_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() out_mem failed",
                       test_num);
    res = allocateSharedMem( &ctx, &inout_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() inout_mem failed",
                       test_num);

    res = openSession( &ctx, &sess, &uuid );
    CHECK_RESULT( res, "test_%02d: openSession() sess failed", test_num );

    // Read in the capsule contents
    fp = fopen(capsule, "rb");
    fseek(fp, 0, SEEK_END);
    encrypt_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    encrypted_data = malloc(encrypt_len + 1);
    fread(encrypted_data, encrypt_len, 1, fp);
    fclose(fp);

    encrypted_data[encrypt_len] = '\0';

    // Read in data contents
    fp = fopen(ptx, "rb");
    fseek(fp, 0, SEEK_END);
    plt_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    plain_text_data = malloc(plt_len + 1);
    fread(plain_text_data, plt_len, 1, fp);
    fclose(fp);

    plain_text_data[plt_len] = '\0';

    res = capsule_open( &sess, &in_mem, &inout_mem, capsule, sizeof(capsule),
                        encrypted_data, encrypt_len, read_data, &read_len );
    CHECK_RESULT( res, "test_%02d: first capsule_open() of capsule %s failed", 
                        test_num, capsule );

    // Compare decrypted data with plaintext data
    COMPARE_LEN( test_num, 1, read_len, plt_len );
    COMPARE_TEXT( test_num, 1, i, read_data, plain_text_data, read_len );

    res = capsule_close( &sess, false, read_data, read_len, &in_mem,
                         &out_mem, &write_len, write_data );
    CHECK_RESULT( res, "test_%02d: capsule_close() %s failed", test_num,
                  capsule );

    // Compare write data with encrypted data. 
    COMPARE_LEN( test_num, 2, write_len, encrypt_len );
    COMPARE_CAPSULE( test_num, 2, i, encrypted_data, write_data, write_len );

    // Second open -- SHOULD NOT FAIL
    // NOTE: cannot memset for SHARED_MEM_SIZE b/c capsule_open realloc'd the
    // memory to fit the particular size sent back (read_len)
    memset(read_data, 0, read_len);
    read_len = 0;

    res = capsule_open( &sess, &in_mem, &inout_mem, capsule, sizeof(capsule),
                        encrypted_data, encrypt_len, read_data, &read_len );
    CHECK_RESULT( res, "test_%02d: second capsule_open() of capsule %s failed", 
                        test_num, capsule );

    // Compare decrypted data with plaintext data
    COMPARE_LEN( test_num, 1, read_len, plt_len );
    COMPARE_TEXT( test_num, 1, i, read_data, plain_text_data, read_len );

    res = closeSession( &sess );
    CHECK_RESULT( res, "test_%02d: closeSession() failed", test_num );

    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() in_mem failed", test_num );

    res = freeSharedMem( &inout_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() inout_mem failed", test_num );

    res = freeSharedMem( &out_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() out_mem failed", test_num );
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "test_%02d: finalizeContext() failed", test_num );

    return res;
}

/* Test no-op capsule with multiple opens and closes of the same capsule.
 * Two part test:
 *  1. Open capsule returns correct decrypted data twice
 *  2. Close capsule returns the exact same encrypted data with no-op policy twice
 */
TEEC_Result test_04() {
    TEEC_Result     res = TEEC_SUCCESS;
    TEEC_Context    ctx;
    TEEC_Session    sess;
    TEEC_UUID       uuid = CAPSULE_UUID;
    char            capsule[] = "/etc/use_case_capsules/test_bio_ehrpatient.capsule";
    char            ptx[] = "/etc/use_case_capsules/test_bio_ehrpatient.data";
    FILE           *fp = NULL;
    char           *encrypted_data, 
                   *read_data,
                   *write_data,
                   *plain_text_data;
    uint32_t        encrypt_len = 0, 
                    read_len = 0, 
                    write_len = SHARED_MEM_SIZE,
                    plt_len = 0;
    int             i = 0, 
                    test_num = 4;

    PRINT_INFO("test_%02d: basic encrypt/decrypt using open and close\n",
                test_num);

    // Need 4096 for test capsule (489 bytes large encrypted, w/o log expansion)
    if (SHARED_MEM_SIZE < 500) {
        res = TEEC_ERROR_GENERIC;
        CHECK_RESULT( res, "test_%02d: SHARED_MEM_SIZE must be greater than 500"
                           " for this test to run. It is %d", test_num, 
                           SHARED_MEM_SIZE);
    }

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    TEEC_SharedMemory inout_mem = { .size = SHARED_MEM_SIZE,
                                    .flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT, };
    TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
                                  .flags = TEEC_MEM_OUTPUT, };

    read_data = malloc(SHARED_MEM_SIZE);
    write_data = malloc(SHARED_MEM_SIZE);

    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "test_%02d: initializeContext() failed", test_num );

    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() in_mem failed", 
                       test_num);
    res = allocateSharedMem( &ctx, &out_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() out_mem failed",
                       test_num);
    res = allocateSharedMem( &ctx, &inout_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() inout_mem failed",
                       test_num);

    res = openSession( &ctx, &sess, &uuid );
    CHECK_RESULT( res, "test_%02d: openSession() sess failed", test_num );

    // Read in the capsule contents
    fp = fopen(capsule, "rb");
    fseek(fp, 0, SEEK_END);
    encrypt_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    encrypted_data = malloc(encrypt_len + 1);
    fread(encrypted_data, encrypt_len, 1, fp);
    fclose(fp);

    encrypted_data[encrypt_len] = '\0';

    // Read in data contents
    fp = fopen(ptx, "rb");
    fseek(fp, 0, SEEK_END);
    plt_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    plain_text_data = malloc(plt_len + 1);
    fread(plain_text_data, plt_len, 1, fp);
    fclose(fp);

    plain_text_data[plt_len] = '\0';

    // First read
    res = capsule_open( &sess, &in_mem, &inout_mem, capsule, sizeof(capsule),
                        encrypted_data, encrypt_len, read_data, &read_len );
    CHECK_RESULT( res, "test_%02d: first capsule_open() of capsule %s failed", 
                        test_num, capsule );

    // Compare decrypted data with plaintext data
    COMPARE_LEN( test_num, 1, read_len, plt_len );
    COMPARE_TEXT( test_num, 1, i, read_data, plain_text_data, read_len );

    // Second read
    // NOTE: cannot memset for SHARED_MEM_SIZE b/c capsule_open realloc'd the
    // memory to fit the particular size sent back (read_len)
    memset(read_data, 0, read_len);
    read_len = 0;

    res = capsule_open( &sess, &in_mem, &inout_mem, capsule, sizeof(capsule),
                        encrypted_data, encrypt_len, read_data, &read_len );
    CHECK_RESULT( res, "test_%02d: second capsule_open() of capsule %s failed", 
                        test_num, capsule );

    // Compare decrypted data with plaintext data
    COMPARE_LEN( test_num, 1, read_len, plt_len );
    COMPARE_TEXT( test_num, 1, i, read_data, plain_text_data, read_len );

    // First close
    res = capsule_close( &sess, false, read_data, read_len, &in_mem,
                         &out_mem, &write_len, write_data );
    CHECK_RESULT( res, "test_%02d: first capsule_close() %s failed", test_num,
                  capsule );

    // Compare write data with encrypted data. 
    COMPARE_LEN( test_num, 2, write_len, encrypt_len );
    COMPARE_CAPSULE( test_num, 2, i, encrypted_data, write_data, write_len );

    // Second close
    memset(write_data, 0, write_len);
    write_len = SHARED_MEM_SIZE;

    res = capsule_close( &sess, false, read_data, read_len, &in_mem,
                         &out_mem, &write_len, write_data );
    CHECK_RESULT( res, "test_%02d: second capsule_close() %s failed", test_num,
                  capsule );

    // Compare write data with encrypted data. 
    COMPARE_LEN( test_num, 2, write_len, encrypt_len );
    COMPARE_CAPSULE( test_num, 2, i, encrypted_data, write_data, write_len );

    res = closeSession( &sess );
    CHECK_RESULT( res, "test_%02d: closeSession() failed", test_num );

    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() in_mem failed", test_num );

    res = freeSharedMem( &inout_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() inout_mem failed", test_num );

    res = freeSharedMem( &out_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() out_mem failed", test_num );
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "test_%02d: finalizeContext() failed", test_num );

    return res;
}

/* Test no-op capsule with open and close.
 * Two part test:
 *  1. Open capsule returns correct decrypted data
 *  2. Close capsule returns the exact same encrypted data with no-op policy
 * Checks:
 *  1. Decrypt works
 *  2. Disassembly and conversion to data works
 *  3. Assembly of components works
 *  4. Encrypt works
 */
TEEC_Result test_03() {
    TEEC_Result     res = TEEC_SUCCESS;
    TEEC_Context    ctx;
    TEEC_Session    sess;
    TEEC_UUID       uuid = CAPSULE_UUID;
    char            capsule[] = "/etc/use_case_capsules/test_bio_ehrpatient.capsule";
    char            ptx[] = "/etc/use_case_capsules/test_bio_ehrpatient.data";
    FILE           *fp = NULL;
    char           *encrypted_data, 
                   *read_data,
                   *write_data,
                   *plain_text_data;
    uint32_t        encrypt_len = 0, 
                    read_len = 0, 
                    write_len = SHARED_MEM_SIZE,
                    plt_len = 0;
    int             i = 0, 
                    test_num = 3;

    PRINT_INFO("test_%02d: basic encrypt/decrypt using open and close\n",
                test_num);

    // Need 4096 for test capsule (489 bytes large encrypted, w/o log expansion)
    if (SHARED_MEM_SIZE < 500) {
        res = TEEC_ERROR_GENERIC;
        CHECK_RESULT( res, "test_%02d: SHARED_MEM_SIZE must be greater than 500"
                           " for this test to run. It is %d", test_num, 
                           SHARED_MEM_SIZE);
    }

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    TEEC_SharedMemory inout_mem = { .size = SHARED_MEM_SIZE,
                                    .flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT, };
    TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
                                  .flags = TEEC_MEM_OUTPUT, };

    read_data = malloc(SHARED_MEM_SIZE);
    write_data = malloc(SHARED_MEM_SIZE);

    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "test_%02d: initializeContext() failed", test_num );

    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() in_mem failed", 
                       test_num);
    res = allocateSharedMem( &ctx, &out_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() out_mem failed",
                       test_num);
    res = allocateSharedMem( &ctx, &inout_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() inout_mem failed",
                       test_num);

    res = openSession( &ctx, &sess, &uuid );
    CHECK_RESULT( res, "test_%02d: openSession() sess failed", test_num );

    // Read in the capsule contents
    fp = fopen(capsule, "rb");
    fseek(fp, 0, SEEK_END);
    encrypt_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    encrypted_data = malloc(encrypt_len + 1);
    fread(encrypted_data, encrypt_len, 1, fp);
    fclose(fp);

    encrypted_data[encrypt_len] = '\0';

    // Read in data contents
    fp = fopen(ptx, "rb");
    fseek(fp, 0, SEEK_END);
    plt_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    plain_text_data = malloc(plt_len + 1);
    fread(plain_text_data, plt_len, 1, fp);
    fclose(fp);

    plain_text_data[plt_len] = '\0';

    res = capsule_open( &sess, &in_mem, &inout_mem, capsule, sizeof(capsule),
                        encrypted_data, encrypt_len, read_data, &read_len );
    CHECK_RESULT( res, "test_%02d: capsule_open() of capsule %s failed", 
                        test_num, capsule );

    // Compare decrypted data with plaintext data
    COMPARE_LEN( test_num, 1, read_len, plt_len );

    COMPARE_TEXT( test_num, 1, i, read_data, plain_text_data, read_len );

    res = capsule_close( &sess, false, read_data, read_len, &in_mem,
                         &out_mem, &write_len, write_data );
    CHECK_RESULT( res, "test_%02d: capsule_close() %s failed", test_num,
                  capsule );

    // Compare write data with encrypted data. 
    COMPARE_LEN( test_num, 2, write_len, encrypt_len );
    COMPARE_CAPSULE( test_num, 2, i, encrypted_data, write_data, write_len );

    res = closeSession( &sess );
    CHECK_RESULT( res, "test_%02d: closeSession() failed", test_num );

    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() in_mem failed", test_num );

    res = freeSharedMem( &inout_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() inout_mem failed", test_num );

    res = freeSharedMem( &out_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() out_mem failed", test_num );
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "test_%02d: finalizeContext() failed", test_num );

    return res;

}

/* Register AES keys and credentials with the TA */
TEEC_Result test_02() {
    char            key[STATE_SIZE] = "cred";
    char            val[STATE_SIZE];
    char            key_random[STATE_SIZE] = "num_access";
    char            val_random[STATE_SIZE] = "0";
    char            key_doct[STATE_SIZE] = "doctor";
    char            val_doct[STATE_SIZE] = "doc1";
    char            key_insu[STATE_SIZE] = "insurer";
    char            val_insu[STATE_SIZE] = "ins1";
    char            val_get[STATE_SIZE];
    TEEC_Result     res = TEEC_SUCCESS;
    TEEC_Context    ctx;
    TEEC_Session    sess;
    TEEC_UUID       uuid = CAPSULE_UUID;
    int             i, test_num = 2;

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
                                  .flags = TEEC_MEM_OUTPUT, };
    
    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "test_%02d: initializeContext() failed", test_num );

    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() failed", test_num );
    
    res = allocateSharedMem( &ctx, &out_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() failed", test_num );

    res = openSession( &ctx, &sess, &uuid );
    CHECK_RESULT( res, "test_%02d: openSession() failed", test_num );

    PRINT_INFO("test_%02d: get/set state operations\n", test_num);
    for( i = 0; i < sizeof( capsule_data_array ) /
                    sizeof( struct capsule_data ); i++ ) {
        // set cred state to wrong value
        res = capsule_set_state( &sess, &in_mem, key, STATE_SIZE, 
                                 val_random, STATE_SIZE, 
                                 *(uint32_t*) (void*) capsule_data_array[i].id );
        CHECK_RESULT( res, "test_%02d: capsule_set_state() key %s -> val %s"
                           " for %s failed", test_num, key, val_random, 
                           capsule_data_array[i].str );

        // reset the cred state to the right value
        memset( val, 0, sizeof(val) );
        memcpy( val, capsule_data_array[i].cred, 
                sizeof( capsule_data_array[i].cred ) );
        
        res = capsule_set_state( &sess, &in_mem, key, STATE_SIZE,
                                 val, STATE_SIZE, 
                                 *(uint32_t*) (void*) capsule_data_array[i].id );
        CHECK_RESULT( res, "test_%02d: capsule_set_state() key %s -> val %s"
                           " for %s failed", test_num, key, val, 
                           capsule_data_array[i].str );
        
        // setting another random state to see if we can add multiple
        // states 
        res = capsule_set_state( &sess, &in_mem, key_random, STATE_SIZE,
                                 val_random, STATE_SIZE, 
                                 *(uint32_t*) (void*) capsule_data_array[i].id );
        CHECK_RESULT( res, "test_%02d: capsule_set_state() key %s -> val %s"
                           " for %s failed", test_num, key_random, val_random, 
                           capsule_data_array[i].str );

        // get the two states to see if they are correct 
        res = capsule_get_state( &sess, &in_mem, &out_mem, key, STATE_SIZE, 
                                 val_get, STATE_SIZE, 
                                 *(uint32_t*) (void*) capsule_data_array[i].id );
        CHECK_RESULT( res, "test_%02d: capsule_get_state() key %s failed for %s",
                           test_num, key, capsule_data_array[i].str );

        if( strcmp( val, val_get) != 0 ) {
            CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT, 
                         "test_%02d: capsule state op for key %s results did "
                         " not match (%s) (%s)", test_num, key, val, val_get );
        }
    
        res = capsule_get_state( &sess, &in_mem, &out_mem, key_random, 
                                 STATE_SIZE, val_get, STATE_SIZE, 
                                 *(uint32_t*) (void*) capsule_data_array[i].id );
        CHECK_RESULT( res, "test_%02d: capsule_get_state() key %s failed for %s",
                           test_num, key_random, capsule_data_array[i].str );

        if( strcmp( val_random, val_get) != 0 ) {
            CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT, 
                         "test_%02d: capsule state op for key %s results did "
                         " not match (%s) (%s)", test_num, key_random, 
                         val_random, val_get );
        }
    }

    res = capsule_set_state( &sess, &in_mem, key_doct, STATE_SIZE, 
                            val_doct, STATE_SIZE,
                            *(uint32_t*) (void*) capsule_data_array[32].id );
    res = capsule_set_state( &sess, &in_mem, key_insu, STATE_SIZE, 
                            val_insu, STATE_SIZE,
                            *(uint32_t*) (void*) capsule_data_array[32].id);

    res = closeSession( &sess );
    CHECK_RESULT( res, "test_%02d: closeSession()", test_num );

    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem()", test_num );

    res = freeSharedMem( &out_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem()", test_num );
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "test_%02d: finalizeContext()", test_num );

    return res;
}


/* Tests allocation of shared memory and initialization
 * of a context and session */
TEEC_Result test_01() {
    TEEC_Result     res = TEEC_SUCCESS;
    TEEC_Context    ctx;
    TEEC_Session    sess1;
    TEEC_Session    sess2;
    TEEC_UUID       uuid = CAPSULE_UUID;
    int             test_num = 1;

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    TEEC_SharedMemory inout_mem = { .size = SHARED_MEM_SIZE,
                                    .flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT, };
    TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
                                  .flags = TEEC_MEM_OUTPUT, };

    PRINT_INFO("test_%02d: allocation of shared mem and initialization\n", test_num);

    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "test_%02d: initializeContext() failed", test_num );

    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() in_mem failed", 
                       test_num );
    res = allocateSharedMem( &ctx, &out_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() out_mem failed", 
                       test_num );
    res = allocateSharedMem( &ctx, &inout_mem );
    CHECK_RESULT( res, "test_%02d: allocateSharedMem() inout_mem failed", 
                       test_num );

    res = openSession( &ctx, &sess1, &uuid );
    CHECK_RESULT( res, "test_%02d: openSession() sess1 failed", test_num );

    // Race condition with opening two sessions
    sleep(3);

    res = openSession( &ctx, &sess2, &uuid );
    CHECK_RESULT( res, "test_%02d: openSession() sess2 failed", test_num );
    
    res = closeSession( &sess1 );
    CHECK_RESULT( res, "test_%02d: closeSession() sess1 failed", test_num );

    res = closeSession( &sess2 );
    CHECK_RESULT( res, "test_%02d: closeSession() sess2 failed", test_num );
    
    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() in_mem failed", test_num );
    res = freeSharedMem( &out_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() out_mem failed", test_num );
    res = freeSharedMem( &inout_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() inout_mem failed", 
                       test_num );
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "test_%02d: finalizeContext() failed", test_num );

    return res;

}

TEEC_Result register_keys() {
    TEEC_Result     res = TEEC_SUCCESS;
    TEEC_Context    ctx;
    TEEC_Session    sess;
    TEEC_UUID       uuid = CAPSULE_UUID;
    int             i;

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    
    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "register_keys: initializeContext() failed");

    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "register_keys: allocateSharedMem() failed");

    res = openSession( &ctx, &sess, &uuid );
    CHECK_RESULT( res, "register_keys: openSession() failed");

    /* Test key registration */
    PRINT_INFO("register_keys: registering...\n");
    for( i = 0; i < sizeof( capsule_data_array ) /
                    sizeof( struct capsule_data ); i++ ) {
        res = register_aes_key( &sess, capsule_data_array[i].id,
                                key_std, sizeof(key_std),
                                iv_std, sizeof(iv_std), 
                                &in_mem );
        CHECK_RESULT( res, "register_keys: register_aes_key() %s failed",
                           capsule_data_array[i].str );
    }

    res = closeSession( &sess );
    CHECK_RESULT( res, "register_keys: closeSession()");

    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "register_keys: freeSharedMem()");
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "register_keys: finalizeContext()");

    return res;
}

static void usage(void) {
    printf( "./test MODE\n"
            "MODE: FULL or REGISTER_KEYS or BENCHMARK or TEST_CAPSULES\n" );
}

int main(int argc, char *argv[]) {
    
    TEEC_Result res;
    int         test_num = 0;  

    if( (strcmp( argv[1], "BENCHMARK" ) == 0 && argc != 5) ) {
        usage();
        printf( "\tFor mode BENCHMARK: ./capsule_test BENCHMARK <num_iter> <capsule_path> <plaintext_path>\n\tBe sure to provide the full path for the capsule and plain text files.\n" );
        return 0;
    }

    if ( (strcmp( argv[1], "BENCHMARK" ) != 0 && argc != 2) ) {
        usage();
        return 0;
    }

    if( strcmp( argv[1], "FULL" ) != 0 && 
        strcmp( argv[1], "REGISTER_KEYS" ) != 0 &&
        strcmp( argv[1], "BENCHMARK" ) != 0 &&
        strcmp( argv[1], "TEST_CAPSULES" ) != 0 &&
        strcmp( argv[1], "MEMORY" ) != 0 ) {
        usage();
        return 0;
    }

    openlog("capsule_test", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    if( strcmp( argv[1], "REGISTER_KEYS" ) == 0 ) {
        res = register_keys();
        CHECK_RESULT( res, "register_keys: failed");
        PRINT_INFO( "register_keys: passed\n" );
    } else if( strcmp( argv[1], "FULL" ) == 0 ) {
        test_num = 1;
        res = test_01();
        CHECK_RESULT( res, "test_%02d: failed", test_num );
        PRINT_INFO( "test_%02d: passed\n", test_num );
    
        test_num = 2;
        res = test_02();
        CHECK_RESULT( res, "test_%02d: failed", test_num );
        PRINT_INFO( "test_%02d: passed\n", test_num );

        test_num = 3;
        res = test_03();
        CHECK_RESULT( res, "test_%02d: failed", test_num );
        PRINT_INFO( "test_%02d: passed\n", test_num );

        test_num = 4;
        res = test_04();
        CHECK_RESULT( res, "test_%02d: failed", test_num );
        PRINT_INFO( "test_%02d: passed\n", test_num );

        test_num = 5;
        res = test_05();
        CHECK_RESULT( res, "test_%02d: failed", test_num );
        PRINT_INFO( "test_%02d: passed\n", test_num );

        test_num = 6;
        res = test_06();
        CHECK_RESULT( res, "test_%02d: failed", test_num );
        PRINT_INFO( "test_%02d: passed\n", test_num );

        // test_num = 7;
        // res = test_07();
        // CHECK_RESULT( res, "test_%02d: failed", test_num );
        // PRINT_INFO( "test_%02d: passed\n", test_num );
    
    } else if( strcmp( argv[1], "TEST_CAPSULES" ) == 0 ) {
        
        // res = test_10();
        // CHECK_RESULT( res, "test_10: failed" );
        // PRINT_INFO( "test_10: passed\n" );

    } else if( strcmp( argv[1], "BENCHMARK" ) == 0 ) {
        // res = benchmark_capsule( argv[3], argv[4], atoi(argv[2] ) );
        // CHECK_RESULT( res, "benchmark of %s vs. %s failed", argv[3], argv[4] );
        // PRINT_INFO( "benchmark of %s vs. %s finished\n", argv[3], argv[4] );
    } else if( strcmp( argv[1], "MEMORY" ) == 0 ) {
        // res = test_11();
        // CHECK_RESULT( res, "memory test of failed");
        // PRINT_INFO( "memory test finished \n");
    }

    closelog();

    return 0;
}
