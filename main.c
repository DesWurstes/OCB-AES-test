#include <stdio.h>

#include "ocb-new/ocb.h"
#include "ocb-reference/ocb.h"

#define rdrand32 __builtin_ia32_rdrand32_step
#define rdrand64 __builtin_ia32_rdrand64_step
#define long long long

const unsigned char en[3] = "EN";
const unsigned char ck[3] = "CK";
const unsigned char de[3] = "DE";

int main(void) {
  const unsigned char* errdesc;
  unsigned int itr = 0, diff, alen, mlen;
  long unsigned int _key[4], _nonce[2], _associated_data[8], _message[8],
    _out1[10], _out2[10];
  unsigned char * key = (unsigned char *) _key, * nonce = (unsigned char *) _nonce, * associated_data = (unsigned char *) _associated_data,
  * message = (unsigned char *) _message, * out1 = (unsigned char *) _out1, * out2 = (unsigned char *) _out2;
  ae_ctx ctx;
  if (!rdrand32(&diff)) {
    puts("RNG failed.");
    return 1;
  }
  puts("Starting...");
test:
  rdrand32(&alen);
  rdrand32(&mlen);
  alen %= 64;
  mlen %= 64;
  for (int i = 0; i < 32; i += 8)
    rdrand64((long unsigned int *) &_key[i]);
  for (int i = 0; i < 64; i += 8)
    rdrand64((long unsigned int *) &_associated_data[i]);
  for (int i = 0; i < 64; i += 8)
    rdrand64((long unsigned int *) &_message[i]);

  rdrand64((long unsigned int *) &_nonce[0]);
  rdrand32((unsigned int *) &_nonce[8]);

  ocb_encrypt(key, nonce, 12,
    message, mlen, associated_data,
    alen, out1);
  ae_clear(&ctx);
  ae_init(&ctx, key, 32, 12);
  if (ae_encrypt(&ctx, nonce, message, mlen, associated_data, alen, out2, NULL, 1) <= 0) {
    puts("Reference error.");
    return 1;
  }
  diff = 0;
  for (int i = 0, k = mlen + 16; i < k; i++)
    diff ^= out1[i];
  for (int i = 0, k = mlen + 16; i < k; i++)
    diff ^= out2[i];
  if (diff) {
    errdesc = en;
    goto fail;
  }
  if (ocb_decrypt(key, nonce, 12,
    out1, mlen, associated_data,
    alen, out2)) {
    errdesc = ck;
    goto fail;
  }
  for (int i = 0; i < mlen; i++)
    diff ^= message[i];
  for (int i = 0; i < mlen; i++)
    diff ^= out2[i];
  if (diff) {
    errdesc = de;
    goto fail;
  }
  if (0) {
  fail:
    printf("---TEST FAILED: %sCODE ERROR---\nKey:\n", errdesc);
    for (int i = 0; i < 32; i++)
      printf("%.2x, ", (unsigned int) key[i]);
    printf("\n\nIteration: %u\n", itr);
    puts("\n\nNonce:");
    for (int i = 0; i < 12; i++)
      printf("%.2x, ", (unsigned int) nonce[i]);
    puts("\n\nAssociated data:");
    for (int i = 0; i < alen; i++)
      printf("%.2x, ", (unsigned int) associated_data[i]);
    puts("\n\nMessage:");
    for (int i = 0; i < mlen; i++)
      printf("%.2x, ", (unsigned int) message[i]);
    puts("");
    return 1;
  }
  if (itr++ != 100000)
    goto test;
  puts("100k TESTS PASS!");
  return 0;
}
