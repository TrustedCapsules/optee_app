#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <capsule.h>
#include <aes_keys.h>
#include "err_ta.h"
#include "key_data.h"
#include "capsule_benchmark.h"
#include "capsule_command.h"

/* Read test of a small capsule file that is < 1 chunk */
TEEC_Result test_03() {

    TEEC_Result     res = TEEC_SUCCESS;
    TEEC_Context    ctx;
    TEEC_Session    sess;
    TEEC_UUID       uuid = CAPSULE_UUID;
    char            capsule[] = "/etc/other_capsules/bio.capsule";
    // char            ptx[] = "/etc/other_capsules/bio.data";
    // FILE           *fp = NULL;
    // uint32_t        ns, nr, i, rlen;
    // char            read_cap[1024];
    // char            read_ptx[1024];
    int             pid = 12345;
    int             fd = 10;

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
                                  .flags = TEEC_MEM_OUTPUT, };

    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "test_03: initializeContext() failed" );

    
    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "test_03: allocateSharedMem() failed" );
    
    
    res = allocateSharedMem( &ctx, &out_mem );
    CHECK_RESULT( res, "test_03: allocateSharedMem() failed" );

    
    res = openSession( &ctx, &sess, &uuid );
    CHECK_RESULT( res, "test_03: openSession() failed" );

    
    res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd );
    CHECK_RESULT( res, "test_03: capsule_open() of capsule %s failed",
                        capsule );

    res = capsule_open( &sess, &in_mem, capsule, sizeof(capsule), pid, fd+1 );
    CHECK_RESULT( res, "test_03: capsule_open() of capsule %s failed",
                        capsule );
    
/*
    fp = fopen( ptx, "rb" );
    if( fp == NULL ) {
        CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT,
                      "test_03: fopen() of capsule ptx %s failed", 
                      ptx );
    }   

    // Perform a read that is larger than the file
    nr = 0;
    rlen = 512; 
    
    res = capsule_lseek( &sess, 0, START, &ns, pid, fd );
    CHECK_RESULT( res, "test_03: capsule_lseek() pos %u failed", ns );
    
    res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
    CHECK_RESULT( res, "test_03: capsule_read() %u B of %u B at"
                       " pos %u failed", nr, rlen, ns );

    ns = fseek( fp, ns, SEEK_SET ); 
    nr = fread( read_ptx, sizeof(char), rlen, fp ); 

    COMPARE_TEXT( 3, 1, i, read_cap, read_ptx, nr );
    
    // Peform a small read (1 chunk) in the middle of the file
    nr = 0;
    rlen = 100; 
    
    res = capsule_lseek( &sess, 10, START, &ns, pid, fd );
    CHECK_RESULT( res, "test_03: capsule_lseek() pos %u failed", ns );
    res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
    CHECK_RESULT( res, "test_03: capsule_read() %u B of %u B at"
                       " pos %u failed", nr, rlen, ns );
    
    ns = fseek( fp, ns, SEEK_SET ); 
    nr = fread( read_ptx, sizeof(char), rlen, fp ); 
    
    COMPARE_TEXT( 3, 2, i, read_cap, read_ptx, nr );

    // Peform a large read (>1 chunk) in the middle of the file
    nr = 0;
    rlen = 600;
    
    res = capsule_lseek( &sess, 800, START, &ns, pid, fd );
    CHECK_RESULT( res, "test_03: capsule_lseek() pos %u failed", ns );
    res = capsule_read( &sess, &out_mem, read_cap, rlen, &nr, pid, fd );
    CHECK_RESULT( res, "test_03: capsule_read() %u B of %u B at"
                       " pos %u failed", nr, rlen, ns );
    
    ns = fseek( fp, ns, SEEK_SET ); 
    nr = fread( read_ptx, sizeof(char), rlen, fp ); 
    
    COMPARE_TEXT( 3, 3, i, read_cap, read_ptx, nr );

    fclose( fp );
*/
    res = capsule_close( &sess, pid, fd );
    CHECK_RESULT( res, "test_03: capsule_close() %s failed", 
                  capsule );

    res = capsule_close( &sess, pid, fd+1 );
    CHECK_RESULT( res, "test_03: capsule_close() %s failed", 
                  capsule );
    
    res = closeSession( &sess );
    CHECK_RESULT( res, "test_03: closeSession() failed" );

    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "test_03: freeSharedMem() in_mem failed" );

    res = freeSharedMem( &out_mem );
    CHECK_RESULT( res, "test_03: freeSharedMem() out_mem failed" );
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "test_03: finalizeContext() failed" );

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
    int             i;

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
                                  .flags = TEEC_MEM_OUTPUT, };
    
    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "test_02: initializeContext() failed" );

    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "test_02: allocateSharedMem() failed" );
    
    res = allocateSharedMem( &ctx, &out_mem );
    CHECK_RESULT( res, "test_02: allocateSharedMem() failed" );

    res = openSession( &ctx, &sess, &uuid );
    CHECK_RESULT( res, "test_02: openSession() failed" );

    /* Test key registration */

    for( i = 0; i < sizeof( capsule_data_array ) /
                    sizeof( struct capsule_data ); i++ ) {
        res = register_aes_key( &sess, capsule_data_array[i].id,
                                key_std, sizeof(key_std),
                                iv_std, sizeof(iv_std), 
                                capsule_data_array[i].chunk_size,
                                &in_mem );
        CHECK_RESULT( res, "test_02: register_aes_key() %s failed", 
                           capsule_data_array[i].str );
    }

    for( i = 0; i < sizeof( capsule_data_array ) /
                    sizeof( struct capsule_data ); i++ ) {
        // set cred state to wrong value
        res = capsule_set_state( &sess, &in_mem, key, STATE_SIZE, 
                                 val_random, STATE_SIZE, 
                                 *(uint32_t*) (void*) capsule_data_array[i].id );
        CHECK_RESULT( res, "test_02: capsule_set_state() key %s -> val %s"
                           " for %s failed", key, val_random, 
                           capsule_data_array[i].str );

        // reset the cred state to the right value
        memset( val, 0, sizeof(val) );
        memcpy( val, capsule_data_array[i].cred, 
                sizeof( capsule_data_array[i].cred ) );
        
        res = capsule_set_state( &sess, &in_mem, key, STATE_SIZE,
                                 val, STATE_SIZE, 
                                 *(uint32_t*) (void*) capsule_data_array[i].id );
        CHECK_RESULT( res, "test_02: capsule_set_state() key %s -> val %s"
                           " for %s failed", key, val, capsule_data_array[i].str );
        
        // setting another random state to see if we can add multiple
        // states 
        res = capsule_set_state( &sess, &in_mem, key_random, STATE_SIZE,
                                 val_random, STATE_SIZE, 
                                 *(uint32_t*) (void*) capsule_data_array[i].id );
        CHECK_RESULT( res, "test_02: capsule_set_state() key %s -> val %s"
                           " for %s failed", key_random, val_random, 
                           capsule_data_array[i].str );

        // get the two states to see if they are correct 
        res = capsule_get_state( &sess, &in_mem, &out_mem, key, STATE_SIZE, 
                                 val_get, STATE_SIZE, 
                                 *(uint32_t*) (void*) capsule_data_array[i].id );
        CHECK_RESULT( res, "test_02: capsule_get_state() key %s failed for %s", 
                           key, capsule_data_array[i].str );

        if( strcmp( val, val_get) != 0 ) {
            CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT, 
                         "test_02: capsule state op for key %s results did "
                         " not match (%s) (%s)", key, val, val_get );
        }
    
        res = capsule_get_state( &sess, &in_mem, &out_mem, key_random, 
                                 STATE_SIZE, val_get, STATE_SIZE, 
                                 *(uint32_t*) (void*) capsule_data_array[i].id );
        CHECK_RESULT( res, "test_02: capsule_get_state() key %s failed for %s", 
                           key_random, capsule_data_array[i].str );

        if( strcmp( val_random, val_get) != 0 ) {
            CHECK_RESULT( TEEC_ERROR_CORRUPT_OBJECT, 
                         "test_02: capsule state op for key %s results did "
                         " not match (%s) (%s)", key_random, val_random, val_get );
        }
    }

    res = capsule_set_state( &sess, &in_mem, key_doct, STATE_SIZE, 
                            val_doct, STATE_SIZE,
                            *(uint32_t*) (void*) capsule_data_array[32].id );
    res = capsule_set_state( &sess, &in_mem, key_insu, STATE_SIZE, 
                            val_insu, STATE_SIZE,
                            *(uint32_t*) (void*) capsule_data_array[32].id);

    res = closeSession( &sess );
    CHECK_RESULT( res, "test_02: closeSession()" );

    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "test_02: freeSharedMem()" );

    res = freeSharedMem( &out_mem );
    CHECK_RESULT( res, "test_02: freeSharedMem()" );
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "test_02: finalizeContext()" );

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

    TEEC_SharedMemory in_mem = { .size = SHARED_MEM_SIZE,
                                 .flags = TEEC_MEM_INPUT, };
    TEEC_SharedMemory out_mem = { .size = SHARED_MEM_SIZE,
                                  .flags = TEEC_MEM_OUTPUT, };

    res = initializeContext( &ctx ) ;
    CHECK_RESULT( res, "test_01: initializeContext() failed" );

    res = allocateSharedMem( &ctx, &in_mem );
    CHECK_RESULT( res, "test_01: allocateSharedMem() failed");
    res = allocateSharedMem( &ctx, &out_mem );
    CHECK_RESULT( res, "test_01: allocateSharedMem() failed");

    res = openSession( &ctx, &sess1, &uuid );
    CHECK_RESULT( res, "test_01: openSession() sess1 failed" );

    res = openSession( &ctx, &sess2, &uuid );
    CHECK_RESULT( res, "test_01: openSession() sess2 failed" );
    
    res = closeSession( &sess1 );
    CHECK_RESULT( res, "test_01: closeSession() sess1 failed" );

    res = closeSession( &sess2 );
    CHECK_RESULT( res, "test_01: closeSession() sess2 failed" );
    
    res = freeSharedMem( &in_mem );
    CHECK_RESULT( res, "test_01: freeSharedMem() failed" );

    res = freeSharedMem( &out_mem );
    CHECK_RESULT( res, "test_01: freeSharedMem() failed" );
    
    res = finalizeContext( &ctx );
    CHECK_RESULT( res, "test_01: finalizeContext() failed" );

    return res;

}

static void usage(void) {
    printf( "./test MODE\n"
            "MODE: FULL or REGISTER_KEYS or BENCHMARK or TEST_CAPSULES\n" );
}

int main(int argc, char *argv[]) {
    
    TEEC_Result res;

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

    if( strcmp( argv[1], "REGISTER_KEYS" ) == 0 ) {
        res = test_01();
        CHECK_RESULT( res, "test_01: failed" );
        PRINT_INFO( "test_01: passed\n" );
    
        res = test_02();
        CHECK_RESULT( res, "test_02: failed" );
        PRINT_INFO( "test_02: passed\n" );
    } else if( strcmp( argv[1], "FULL" ) == 0 ) {
        res = test_03();
        CHECK_RESULT( res, "test_03: failed" );
        PRINT_INFO( "test_03: passed\n" );

        // res = test_04();
        // CHECK_RESULT( res, "test_04: failed" );
        // PRINT_INFO( "test_04: passed\n" );
        
        // res = test_05();
        // CHECK_RESULT( res, "test_05: failed" );
        // PRINT_INFO( "test_05: passed\n" );

        // res = test_06();
        // CHECK_RESULT( res, "test_06: failed" );
        // PRINT_INFO( "test_06: passed\n" );

        //res = test_07();
        //CHECK_RESULT( res, "test_07: failed" );
        //PRINT_INFO( "test_07: passed\n" );
    
        //res = test_08();
        //CHECK_RESULT( res, "test_08: failed" );
        //PRINT_INFO( "test_08: passed\n" );
        
        // res = test_09();
        // CHECK_RESULT( res, "test_09: failed" );
        // PRINT_INFO( "test_09: passed\n" );       
    
        // res = test_12();
        // CHECK_RESULT( res, "test_12: failed" );
        // PRINT_INFO( "test_12: passed\n" );
        
        // res = test_13();
        // CHECK_RESULT( res, "test_13: failed" );
        // PRINT_INFO( "test_13: passed\n" );
    
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
    return 0;
}
