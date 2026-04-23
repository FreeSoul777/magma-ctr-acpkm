#include "test_magma.h"

#include "core/magma.h"
#include "utils/utils.h"

#include <stdio.h>
#include <string.h>

int test_magma_rfc8891(void)
{
    printf("=== Test 1: Magma RFC 8891 Basic Tests ===\n\n");
    int all_passed = 1;

    printf("--- A.1. Transformation t ---\n");
    uint32_t t_test_vals[] = {0xfdb97531, 0x2a196f34, 0xebd9f03a, 0xb039bb3d};
    uint32_t t_expected[]  = {0x2a196f34, 0xebd9f03a, 0xb039bb3d, 0x68695433};
    for (int i = 0; i < 4; i++)
    {
        uint32_t res = magma_t_transform(t_test_vals[i]);
        int      ok  = (res == t_expected[i]);
        printf("t(%08x) = %08x [%s]\n", t_test_vals[i], res, ok ? "OK" : "FAIL");
        if (!ok)
        {
            printf("  Expected: %08x\n", t_expected[i]);
            all_passed = 0;
        }
    }
    printf("\n");

    printf("--- A.2. Transformation g ---\n");
    uint32_t g_a[]        = {0xfedcba98, 0x87654321, 0xfdcbc20c, 0x7e791a4b};
    uint32_t g_k[]        = {0x87654321, 0xfdcbc20c, 0x7e791a4b, 0xc76549ec};
    uint32_t g_expected[] = {0xfdcbc20c, 0x7e791a4b, 0xc76549ec, 0x9791c849};
    for (int i = 0; i < 4; i++)
    {
        uint32_t res = magma_g_function(g_a[i], g_k[i]);
        int      ok  = (res == g_expected[i]);
        printf("g[%08x](%08x) = %08x [%s]\n", g_k[i], g_a[i], res, ok ? "OK" : "FAIL");
        if (!ok)
        {
            printf("  Expected: %08x\n", g_expected[i]);
            all_passed = 0;
        }
    }
    printf("\n");

    printf("--- A.3. Key Schedule ---\n");
    uint8_t  test_key[32] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55,
                             0x44, 0x33, 0x22, 0x11, 0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                             0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    uint32_t round_keys[32];
    magma_expand_key(test_key, round_keys);

    uint32_t expected_keys[] = {0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb,
                                0xfcfdfeff, 0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7,
                                0xf8f9fafb, 0xfcfdfeff, 0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3,
                                0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff, 0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3,
                                0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc};

    printf("All round keys (K1..K32):\n");
    int ok_keys = 1;
    for (int i = 0; i < 32; i++)
    {
        int ok = (round_keys[i] == expected_keys[i]);
        printf("K%-2d = %08x [%s]\n", i + 1, round_keys[i], ok ? "OK" : "FAIL");
        if (!ok)
        {
            printf("       Expected: %08x\n", expected_keys[i]);
            ok_keys = 0;
        }
    }
    printf("\nKey schedule: %s\n\n", ok_keys ? "OK" : "FAIL");
    if (!ok_keys)
        all_passed = 0;

    printf("--- A.4/A.5. Full Encryption & Decryption ---\n");
    uint8_t plaintext[8]           = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t expected_ciphertext[8] = {0x4e, 0xe9, 0x01, 0xe5, 0xc2, 0xd8, 0xca, 0x3d};
    uint8_t ciphertext[8], decrypted[8];

    print_hex("Plaintext", plaintext, 8);
    magma_encrypt_block(plaintext, round_keys, ciphertext);
    print_hex("Encrypted", ciphertext, 8);

    int enc_ok = (memcmp(ciphertext, expected_ciphertext, 8) == 0);
    if (!enc_ok)
    {
        print_hex("Expected", expected_ciphertext, 8);
        printf("Encryption test: FAIL\n");
        all_passed = 0;
    }
    else
    {
        printf("Encryption test: OK\n");
    }

    magma_decrypt_block(ciphertext, round_keys, decrypted);
    print_hex("Decrypted", decrypted, 8);

    int dec_ok = (memcmp(decrypted, plaintext, 8) == 0);
    if (!dec_ok)
    {
        print_hex("Expected", plaintext, 8);
        printf("Decryption test: FAIL\n");
        all_passed = 0;
    }
    else
    {
        printf("Decryption test: OK\n");
    }

    printf("\n");
    return all_passed;
}