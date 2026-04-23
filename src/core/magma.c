#include "magma.h"

#include "utils/utils.h"

#include <string.h>

static const uint8_t sbox[8][16] = {
    {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1}, {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
    {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0}, {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
    {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12}, {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
    {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7}, {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}};

uint32_t magma_t_transform(uint32_t a)
{
    uint32_t res = 0;
    for (int i = 0; i < 8; i++)
    {
        uint8_t nibble   = (a >> (4 * i)) & 0xF;
        uint8_t replaced = sbox[i][nibble];
        res |= (replaced << (4 * i));
    }
    return res;
}

uint32_t magma_g_function(uint32_t a, uint32_t k)
{
    uint32_t sum = a + k;
    uint32_t t   = magma_t_transform(sum);
    return (t << 11) | (t >> (32 - 11));
}

void magma_expand_key(const uint8_t key[32], uint32_t round_keys[32])
{
    uint32_t k[8];
    for (int i = 0; i < 8; i++)
    {
        k[i] = ((uint32_t)key[i * 4 + 0] << 24) | ((uint32_t)key[i * 4 + 1] << 16) | ((uint32_t)key[i * 4 + 2] << 8)
               | ((uint32_t)key[i * 4 + 3]);
    }
    for (int i = 0; i < 24; i++)
        round_keys[i] = k[i % 8];
    for (int i = 0; i < 8; i++)
        round_keys[24 + i] = k[7 - i];
    secure_zero(k, sizeof(k));
}

void magma_encrypt_block(const uint8_t plaintext[8], const uint32_t round_keys[32], uint8_t ciphertext[8])
{
    uint32_t a1 = ((uint32_t)plaintext[0] << 24) | ((uint32_t)plaintext[1] << 16) | ((uint32_t)plaintext[2] << 8)
                  | ((uint32_t)plaintext[3]);
    uint32_t a0 = ((uint32_t)plaintext[4] << 24) | ((uint32_t)plaintext[5] << 16) | ((uint32_t)plaintext[6] << 8)
                  | ((uint32_t)plaintext[7]);

    uint32_t left = a1, right = a0;
    for (int round = 0; round < 32; round++)
    {
        uint32_t new_left  = right;
        uint32_t new_right = left ^ magma_g_function(right, round_keys[round]);
        left               = new_left;
        right              = new_right;
    }

    ciphertext[0] = (right >> 24) & 0xFF;
    ciphertext[1] = (right >> 16) & 0xFF;
    ciphertext[2] = (right >> 8) & 0xFF;
    ciphertext[3] = right & 0xFF;
    ciphertext[4] = (left >> 24) & 0xFF;
    ciphertext[5] = (left >> 16) & 0xFF;
    ciphertext[6] = (left >> 8) & 0xFF;
    ciphertext[7] = left & 0xFF;
}

void magma_decrypt_block(const uint8_t ciphertext[8], const uint32_t round_keys[32], uint8_t plaintext[8])
{
    uint32_t b1 = ((uint32_t)ciphertext[0] << 24) | ((uint32_t)ciphertext[1] << 16) | ((uint32_t)ciphertext[2] << 8)
                  | ((uint32_t)ciphertext[3]);
    uint32_t b0 = ((uint32_t)ciphertext[4] << 24) | ((uint32_t)ciphertext[5] << 16) | ((uint32_t)ciphertext[6] << 8)
                  | ((uint32_t)ciphertext[7]);

    uint32_t left = b1, right = b0;
    for (int round = 31; round >= 0; round--)
    {
        uint32_t new_left  = right;
        uint32_t new_right = left ^ magma_g_function(right, round_keys[round]);
        left               = new_left;
        right              = new_right;
    }

    plaintext[0] = (right >> 24) & 0xFF;
    plaintext[1] = (right >> 16) & 0xFF;
    plaintext[2] = (right >> 8) & 0xFF;
    plaintext[3] = right & 0xFF;
    plaintext[4] = (left >> 24) & 0xFF;
    plaintext[5] = (left >> 16) & 0xFF;
    plaintext[6] = (left >> 8) & 0xFF;
    plaintext[7] = left & 0xFF;
}

int self_test(void)
{
    uint8_t test_key[32] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55,
                            0x44, 0x33, 0x22, 0x11, 0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                            0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

    uint32_t round_keys[32];
    magma_expand_key(test_key, round_keys);

    uint8_t plaintext[8] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t expected[8]  = {0x4e, 0xe9, 0x01, 0xe5, 0xc2, 0xd8, 0xca, 0x3d};
    uint8_t ciphertext[8], decrypted[8];

    magma_encrypt_block(plaintext, round_keys, ciphertext);
    if (memcmp(ciphertext, expected, 8) != 0)
        return 0;

    magma_decrypt_block(ciphertext, round_keys, decrypted);
    if (memcmp(decrypted, plaintext, 8) != 0)
        return 0;

    return 1;
}