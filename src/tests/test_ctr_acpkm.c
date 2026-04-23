#include "test_ctr_acpkm.h"

#include "core/ctr_acpkm.h"
#include "utils/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const uint8_t test_master_key[32] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55,
                                            0x44, 0x33, 0x22, 0x11, 0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                                            0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

int test_ctr_acpkm(void)
{
    printf("=== Test 2: CTR-ACPKM Mode (ГОСТ Р 34.13-2015) ===\n\n");
    int all_passed = 1;

    printf("--- 2.1. ACPKM Key Transform (K_{i+1} = ACPKM(K_i)) ---\n");

    ctr_acpkm_ctx ctx_test;
    ctr_acpkm_init(&ctx_test, test_master_key, 0, 2, 0);

    uint32_t first_key = ctx_test.round_keys[0];
    printf("K1 (first 32-bit): %08x\n", first_key);

    uint8_t dummy[8] = {0};
    uint8_t out[8];

    ctr_acpkm_crypt(&ctx_test, dummy, out, 8);
    ctr_acpkm_crypt(&ctx_test, dummy, out, 8);
    ctr_acpkm_crypt(&ctx_test, dummy, out, 8);

    uint32_t second_key = ctx_test.round_keys[0];
    printf("K2 (first 32-bit): %08x\n", second_key);

    if (first_key != second_key)
    {
        printf("Second key is different from first: OK\n");
    }
    else
    {
        printf("Second key is different from first: FAIL\n");
        all_passed = 0;
    }
    ctr_acpkm_destroy(&ctx_test);
    printf("\n");

    printf("--- 2.2. CTR-ACPKM Encryption/Decryption ---\n");

    const char* message    = "Hello, World! This is a test message for CTR-ACPKM mode with Magma cipher.";
    size_t      msg_len    = strlen(message);
    uint8_t*    plaintext  = (uint8_t*)malloc(msg_len);
    uint8_t*    ciphertext = (uint8_t*)malloc(msg_len);
    uint8_t*    decrypted  = (uint8_t*)malloc(msg_len);

    memcpy(plaintext, message, msg_len);

    ctr_acpkm_ctx enc_ctx, dec_ctx;
    uint64_t      iv         = 0x1234567890ABCDEFULL;
    uint64_t      max_blocks = 1000;

    printf("Message (size=%zu bytes): \"%s\"\n", msg_len, message);
    printf("Initialization vector (IV): 0x%016llx\n", (unsigned long long)iv);
    printf("Section size (max_blocks): %llu blocks (%llu bytes)\n", (unsigned long long)max_blocks,
           (unsigned long long)max_blocks * 8);
    printf("ACPKM re-keying will occur every %llu blocks\n\n", (unsigned long long)max_blocks);

    ctr_acpkm_init(&enc_ctx, test_master_key, iv, max_blocks, 0);
    ctr_acpkm_init(&dec_ctx, test_master_key, iv, max_blocks, 0);

    printf("Encrypting...\n");
    ctr_acpkm_crypt(&enc_ctx, plaintext, ciphertext, msg_len);
    printf("First 16 bytes of ciphertext: ");
    for (int i = 0; i < 16 && i < (int)msg_len; i++)
        printf("%02x", ciphertext[i]);
    printf("...\n");

    printf("Decrypting...\n");
    ctr_acpkm_crypt(&dec_ctx, ciphertext, decrypted, msg_len);

    printf("\nDecrypted message: \"%s\"\n", decrypted);

    int crypt_ok = (memcmp(plaintext, decrypted, msg_len) == 0);
    printf("\nEncryption/Decryption test: %s\n", crypt_ok ? "OK" : "FAIL");
    if (!crypt_ok)
        all_passed = 0;

    ctr_acpkm_destroy(&enc_ctx);
    ctr_acpkm_destroy(&dec_ctx);
    printf("\n");

    printf("--- 2.3. Automatic Re-keying Verification ---\n");

    ctr_acpkm_ctx rekey_ctx;
    ctr_acpkm_init(&rekey_ctx, test_master_key, 0, 2, 0);
    printf("Test (max_blocks=2, section size N=128 bits):\n");

    uint8_t zero[8] = {0};
    uint8_t zero_out[8];

    ctr_acpkm_crypt(&rekey_ctx, zero, zero_out, 8);
    printf("  After block 1: blocks_processed = %lu (key K1)\n", (unsigned long)rekey_ctx.blocks_processed);

    ctr_acpkm_crypt(&rekey_ctx, zero, zero_out, 8);
    printf("  After block 2: blocks_processed = %lu (rekey will happen on next call)\n",
           (unsigned long)rekey_ctx.blocks_processed);

    ctr_acpkm_crypt(&rekey_ctx, zero, zero_out, 8);
    printf("  After block 3: blocks_processed = %lu (rekey to K2, then +1)\n",
           (unsigned long)rekey_ctx.blocks_processed);

    if (rekey_ctx.blocks_processed == 1)
    {
        printf("  Result: OK\n");
    }
    else
    {
        printf("  Result: FAIL\n");
        all_passed = 0;
    }
    ctr_acpkm_destroy(&rekey_ctx);
    printf("\n");

    printf("--- 2.4. Key Lifetime Control (КС3 requirement 2.5) ---\n");

    ctr_acpkm_ctx expired_ctx;
    printf("Creating key with 1 second lifetime...\n");
    ctr_acpkm_init(&expired_ctx, test_master_key, 0, 1000, 1);

    uint8_t test_in[8] = {0};
    uint8_t test_out[8];
    int     result = ctr_acpkm_crypt(&expired_ctx, test_in, test_out, 8);
    printf("Encryption before expiry (t=0s): %s\n", result == 0 ? "ALLOWED" : "REJECTED");

    printf("Waiting 2 seconds...\n");
    sleep(2);
    result = ctr_acpkm_crypt(&expired_ctx, test_in, test_out, 8);
    printf("Encryption after expiry (t=2s): %s\n", result == -1 ? "REJECTED (OK)" : "ALLOWED (FAIL)");
    if (result != -1)
        all_passed = 0;

    ctr_acpkm_destroy(&expired_ctx);
    printf("\n");

    printf("--- 2.5. Key Memory Protection (КС3 requirement 2.1) ---\n");

    ctr_acpkm_ctx mem_ctx;
    ctr_acpkm_init(&mem_ctx, test_master_key, 0, 1000, 0);
    printf("Key memory locked (mlock): %s\n", mem_ctx.key_locked ? "YES (OK)" : "NO (check permissions)");
    ctr_acpkm_destroy(&mem_ctx);
    printf("\n");

    secure_free(plaintext, msg_len);
    secure_free(ciphertext, msg_len);
    secure_free(decrypted, msg_len);

    return all_passed;
}