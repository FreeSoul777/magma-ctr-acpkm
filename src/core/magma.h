#ifndef MAGMA_H
#define MAGMA_H

#include <stddef.h>
#include <stdint.h>

uint32_t magma_t_transform(uint32_t a);
uint32_t magma_g_function(uint32_t a, uint32_t k);

void magma_expand_key(const uint8_t key[32], uint32_t round_keys[32]);
void magma_encrypt_block(const uint8_t plaintext[8], const uint32_t round_keys[32], uint8_t ciphertext[8]);
void magma_decrypt_block(const uint8_t ciphertext[8], const uint32_t round_keys[32], uint8_t plaintext[8]);

int self_test(void);

#endif