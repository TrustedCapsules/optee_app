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

/* Test no-op capsule with open and close.
 * Two part test:
 *  1. Open capsule returns correct decrypted data
 *  2. Close capsule returns the exact same encrypted data with no-op policy
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
                   *read_data = malloc(4096), 
                   *write_data = malloc(4096), 
                   *decrypted_data,
                   *plain_text_data;
    uint32_t        encrypt_len = 0, 
                    read_len = 0, 
                    write_len = 4096, // size of out buffer
                    decrypt_len = 0,
                    plt_len = 0;
    int             i = 0, test_num = 3;

    // Need 4096 for test capsule (2013 bytes large encrypted, w/o log expansion)
    TEEC_SharedMemory in_mem = { .size = 4096,
                                 .flags = TEEC_MEM_INPUT, };
    TEEC_SharedMemory inout_mem = { .size = 4096,
                                    .flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT, };
    TEEC_SharedMemory out_mem = { .size = 4096,
                                  .flags = TEEC_MEM_OUTPUT, };

    // printf("Setting up everything and opening session.\n");
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

    // printf("Reading %s contents\n", capsule);
    // Read in the capsule contents
    fp = fopen(capsule, "rb");
    fseek(fp, 0, SEEK_END);
    encrypt_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    encrypted_data = malloc(encrypt_len + 1);
    fread(encrypted_data, encrypt_len, 1, fp);
    fclose(fp);

    encrypted_data[encrypt_len] = '\0';

    // printf("Reading %s contents\n", ptx);
    // Read in data contents
    fp = fopen(ptx, "rb");
    fseek(fp, 0, SEEK_END);
    plt_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    plain_text_data = malloc(plt_len + 1);
    fread(plain_text_data, plt_len, 1, fp);
    fclose(fp);

    plain_text_data[plt_len] = '\0';

    // printf("Calling capsule open\n");
    res = capsule_open( &sess, &in_mem, &inout_mem, capsule, sizeof(capsule),
                        encrypted_data, encrypt_len, read_data, &read_len );
    CHECK_RESULT( res, "test_%02d: capsule_open() of capsule %s failed", 
                        test_num, capsule );

    // printf("Copying to decrypted_data (size %d)\n", read_len);
    decrypted_data = malloc(read_len);
    // printf("Read_data location: %p\n", &read_data);
    memset(decrypted_data, 0, read_len);
    // printf("Data read: %.*s\n", read_len, read_data);
    memcpy(decrypted_data, read_data, read_len);
    decrypt_len = read_len;
    // printf("Decrypted read: %.*s\n", decrypt_len, decrypted_data);

    // printf("Comparing length (%d, %d)\n", strlen(decrypted_data), plt_len);
    // Compare decrypted data with plaintext data
    COMPARE_LEN( test_num, 1, read_len, plt_len );

    // printf("Comparing data\n");
    COMPARE_TEXT( test_num, 1, i, decrypted_data, plain_text_data, read_len );

    // printf("Calling close for %s\n", capsule);
    res = capsule_close( &sess, false, decrypted_data, decrypt_len, &in_mem,
                         &out_mem, &write_len, write_data );
    CHECK_RESULT( res, "test_%02d: capsule_close() %s failed", test_num,
                  capsule );

    // printf("Write_data location: %p\n", &write_data);

    // PRINT_INFO("Write data: ");
    // for( int i = 0; i < write_len; i++ ) {
    //     PRINT_INFO( "%02x", write_data[i] );
    // }
    // PRINT_INFO("\n");

    // Compare write data with encrypted data. 
    // TODO: cannot compare byte wise because the log and KV store could be
    //       changed. Unless we restrict this test to a no-op capsule.
    // printf("Comparing length (%d, %d)\n", write_len, encrypt_len);
    COMPARE_LEN( test_num, 2, write_len, encrypt_len );
    // printf("Comparing data\n");
    COMPARE_CAPSULE( test_num, 2, i, encrypted_data, write_data, write_len );


    // printf("Closing session\n");
    res = closeSession( &sess );
    CHECK_RESULT( res, "test_%02d: closeSession() failed", test_num );

    // printf("Freeing shared memory\n");
    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() in_mem failed", test_num );

    res = freeSharedMem( &out_mem );
    CHECK_RESULT( res, "test_%02d: freeSharedMem() out_mem failed", test_num );
    
    // printf("Finalizing context\n");
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

    /* Test key registration */

    for( i = 0; i < sizeof( capsule_data_array ) /
                    sizeof( struct capsule_data ); i++ ) {
        res = register_aes_key( &sess, capsule_data_array[i].id,
                                key_std, sizeof(key_std),
                                iv_std, sizeof(iv_std), 
                                capsule_data_array[i].chunk_size,
                                &in_mem );
        CHECK_RESULT( res, "test_%02d: register_aes_key() %s failed", test_num,
                           capsule_data_array[i].str );
    }

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
        test_num = 1;
        res = test_01();
        CHECK_RESULT( res, "test_%02d: failed", test_num );
        PRINT_INFO( "test_%02d: passed\n", test_num );
    
        test_num = 2;
        res = test_02();
        CHECK_RESULT( res, "test_%02d: failed", test_num );
        PRINT_INFO( "test_%02d: passed\n", test_num );
    } else if( strcmp( argv[1], "FULL" ) == 0 ) {
        // Test no-op open and close of a capsule. Checks:
        //  1. Decrypt works
        //  2. Disassembly and conversion to data works
        //  3. Assembly of components works
        //  4. Encrypt works
        test_num = 3;
        res = test_03();
        CHECK_RESULT( res, "test_%02d: failed", test_num );
        PRINT_INFO( "test_%02d: passed\n", test_num );
    
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
