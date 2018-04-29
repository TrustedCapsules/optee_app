/* test the ciphers and hashes using their built-in self-tests */

#include <tomcrypt_test.h>

int cipher_hash_test(void)
{
   int           x;
   unsigned char buf[4096];
   unsigned long n, one;
   prng_state    nprng;

   /* test ciphers */
   for (x = 0; cipher_descriptor[x].name != NULL; x++) {
      DOX(cipher_descriptor[x].test(), cipher_descriptor[x].name);
   }

   /* stream ciphers */
#ifdef LTC_CHACHA
   DO(chacha_test());
#endif
#ifdef LTC_RC4_STREAM
   DO(rc4_stream_test());
#endif
#ifdef LTC_SOBER128_STREAM
   DO(sober128_stream_test());
#endif

   /* test hashes */
   for (x = 0; hash_descriptor[x].name != NULL; x++) {
      DOX(hash_descriptor[x].test(), hash_descriptor[x].name);
   }

   /* SHAKE128 + SHAKE256 tests are a bit special */
   DOX(sha3_shake_test(), "sha3_shake");

   /* test prngs (test, import/export */
   for (x = 0; prng_descriptor[x].name != NULL; x++) {
      DOX(prng_descriptor[x].test(), prng_descriptor[x].name);
      DOX(prng_descriptor[x].start(&nprng), prng_descriptor[x].name);
      DOX(prng_descriptor[x].add_entropy((unsigned char *)"helloworld12", 12, &nprng), prng_descriptor[x].name);
      DOX(prng_descriptor[x].ready(&nprng), prng_descriptor[x].name);
      n = sizeof(buf);
      if (strcmp(prng_descriptor[x].name, "sprng")) {
         one = 1;
         if (prng_descriptor[x].pexport(buf, &one, &nprng) != CRYPT_BUFFER_OVERFLOW) {
            fprintf(stderr, "Error testing pexport with a short buffer (%s)\n", prng_descriptor[x].name);
            return CRYPT_ERROR;
         }
      }
      DOX(prng_descriptor[x].pexport(buf, &n, &nprng), prng_descriptor[x].name);
      prng_descriptor[x].done(&nprng);
      DOX(prng_descriptor[x].pimport(buf, n, &nprng), prng_descriptor[x].name);
      DOX(prng_descriptor[x].pimport(buf, 4096, &nprng), prng_descriptor[x].name); /* try to import larger data */
      DOX(prng_descriptor[x].ready(&nprng), prng_descriptor[x].name);
      if (prng_descriptor[x].read(buf, 100, &nprng) != 100) {
         fprintf(stderr, "Error reading from imported PRNG (%s)!\n", prng_descriptor[x].name);
         return CRYPT_ERROR;
      }
      prng_descriptor[x].done(&nprng);
   }

   return 0;
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */
